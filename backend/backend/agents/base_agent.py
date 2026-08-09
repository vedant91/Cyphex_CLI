"""
CYPHEX — Base Agent Class

Abstract base class that all 10 agents inherit from.
Each agent gets:
  - Its own AgentTerminal for real command execution
  - Cerebras AI integration for intelligent decision-making
  - Vuln tracking and evidence collection
  - Colored console logging
"""

import json
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Union

import httpx

from agents.terminal import AgentTerminal, Colors, AGENT_COLORS
from models.scan import ScanContext, Vuln, Evidence
from models.agent_result import AgentResult
from config import config
from live_log_queue import log_queue


class BaseAgent(ABC):
    """Base class all CYPHEX agents inherit from."""

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        cerebras_key: str = "",
    ):
        self.scan_id = scan_id
        self.target = target_url
        self.cerebras_key = cerebras_key or config.CEREBRAS_API_KEY

        # Each agent gets its own terminal
        self.terminal = AgentTerminal(
            agent_name=self.__class__.__name__,
            target_url=target_url,
            scan_id=scan_id,
        )

        self.vulns: list[Vuln] = []
        self.evidence: list[Evidence] = []
        self.color = AGENT_COLORS.get(self.__class__.__name__, Colors.WHITE)

    @abstractmethod
    async def run(self, context: ScanContext) -> AgentResult:
        """Each agent implements this. Context has data from previous agents."""
        pass

    async def log(self, message: str, level: str = "info"):
        """Log a message to console with color coding."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        agent_tag = f"{self.color}{Colors.BOLD}[{self.__class__.__name__}]{Colors.RESET}"

        level_colors = {
            "info": Colors.WHITE,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "danger": Colors.RED,
            "critical": f"{Colors.BG_RED}{Colors.WHITE}",
        }
        lc = level_colors.get(level, Colors.WHITE)

        print(
            f"  {Colors.DIM}{timestamp}{Colors.RESET} "
            f"{agent_tag} "
            f"{lc}{message}{Colors.RESET}"
        )

    async def add_vuln(self, vuln: Vuln):
        """Register a confirmed vulnerability."""
        self.vulns.append(vuln)
        severity_colors = {
            "Critical": f"{Colors.BG_RED}{Colors.WHITE}",
            "High": Colors.RED,
            "Medium": Colors.YELLOW,
            "Low": Colors.BLUE,
        }
        sc = severity_colors.get(vuln.severity, Colors.WHITE)
        print(
            f"\n  {sc}{Colors.BOLD}"
            f"  [ALERT] VULN FOUND: [{vuln.severity}] {vuln.name} "
            f"(CVSS: {vuln.cvss_score}) "
            f"{Colors.RESET}"
        )
        if vuln.endpoint:
            print(
                f"  {Colors.GRAY}     Endpoint: {vuln.endpoint}{Colors.RESET}"
            )
        if vuln.payload:
            print(
                f"  {Colors.RED}     Payload: {vuln.payload[:100]}{Colors.RESET}"
            )
        print()

    async def call_cerebras(
        self, system_prompt: str, user_prompt: str, max_retries: int = 3
    ) -> str:
        """
        Call AI backend for analysis and decision-making.
        Supports modes: 'local' (Ollama) | 'groq' (cloud) | 'cerebras' (legacy)

        Fallback chain: groq -> ollama -> empty string
        """
        mode = config.AI_BACKEND_MODE

        if mode == "groq":
            result = await self._call_groq(system_prompt, user_prompt, max_retries)
            if result:
                return result
            # Auto-fallback to Ollama if Groq fails
            await self.log("Groq failed -> falling back to local Ollama", "warning")
            return await self._call_ollama(system_prompt, user_prompt, max_retries=2)

        elif mode == "local":
            result = await self._call_ollama(system_prompt, user_prompt, max_retries)
            if result:
                return result
            # Auto-fallback to Groq if Ollama fails and key is available
            if config.GROQ_API_KEY:
                await self.log("Ollama failed -> falling back to Groq cloud", "warning")
                return await self._call_groq(system_prompt, user_prompt, max_retries=2)
            return ""

        else:  # cerebras (legacy)
            return await self._call_cerebras_cloud(system_prompt, user_prompt, max_retries)

    async def _call_groq(
        self, system_prompt: str, user_prompt: str, max_retries: int = 3
    ) -> str:
        """
        Call Groq cloud API (FREE, OpenAI-compatible, 300+ tokens/sec).
        Uses Llama 3.3 70B — same quality as Cerebras was.
        """
        if not config.GROQ_API_KEY:
            await self.log("Groq API key not set — skipping", "warning")
            return ""

        await self.log(f"Calling Groq AI ({config.GROQ_MODEL})...", "info")

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        config.GROQ_API_URL,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {config.GROQ_API_KEY}",
                        },
                        json={
                            "model": config.GROQ_MODEL,
                            "max_tokens": config.GROQ_MAX_TOKENS,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()
                        content = data.get("choices", [{}])[0].get(
                            "message", {}
                        ).get("content", "")
                        await self.log("Groq AI response received [OK]", "success")
                        return content
                    elif response.status_code == 429:
                        wait_time = 5 * (attempt + 1)
                        await self.log(
                            f"Groq rate limited — waiting {wait_time}s...",
                            "warning",
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        await self.log(
                            f"Groq API error {response.status_code}: {response.text[:200]}",
                            "warning",
                        )

            except Exception as e:
                await self.log(
                    f"Groq API attempt {attempt + 1} failed: {e}",
                    "warning",
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        await self.log("Groq API unavailable", "warning")
        return ""

    async def _call_ollama(
        self, system_prompt: str, user_prompt: str, max_retries: int = 3
    ) -> str:
        """Call local Ollama server (runs on laptop GPU or Pi CPU)."""
        await self.log(f"Calling local AI ({config.OLLAMA_MODEL})...", "info")

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=180.0) as client:
                    response = await client.post(
                        f"{config.OLLAMA_URL}/api/chat",
                        json={
                            "model": config.OLLAMA_MODEL,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                            "stream": False,
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()
                        content = data.get("message", {}).get("content", "")
                        await self.log("Local AI response received [OK]", "success")
                        return content
                    else:
                        await self.log(
                            f"Ollama error {response.status_code}: {response.text[:200]}",
                            "warning",
                        )

            except Exception as e:
                await self.log(
                    f"Ollama attempt {attempt + 1} failed: {e}",
                    "warning",
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        await self.log("Local AI unavailable", "warning")
        return ""

    async def _call_cerebras_cloud(
        self, system_prompt: str, user_prompt: str, max_retries: int = 3
    ) -> str:
        """Call Cerebras cloud API (legacy — currently broken)."""
        await self.log("Calling Cerebras AI...", "info")

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        config.CEREBRAS_API_URL,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {self.cerebras_key}",
                        },
                        json={
                            "model": config.CEREBRAS_MODEL,
                            "max_tokens": config.CEREBRAS_MAX_TOKENS,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                    )

                    if response.status_code == 200:
                        data = response.json()
                        content = data.get("choices", [{}])[0].get(
                            "message", {}
                        ).get("content", "")
                        await self.log("Cerebras response received", "success")
                        return content
                    else:
                        await self.log(
                            f"Cerebras API error {response.status_code}: {response.text[:200]}",
                            "warning",
                        )

            except Exception as e:
                await self.log(
                    f"Cerebras API attempt {attempt + 1} failed: {e}",
                    "warning",
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        await self.log("Cerebras API unavailable — using fallback logic", "warning")
        return ""

    def _parse_json(self, text: str) -> Optional[Union[dict, list]]:
        """Extract JSON from text (handles markdown code blocks)."""
        if not text:
            return None
        # Strip markdown code blocks
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON array or object
            import re
            array_match = re.search(r'\[[\s\S]*\]', text)
            if array_match:
                try:
                    return json.loads(array_match.group())
                except json.JSONDecodeError:
                    pass
            obj_match = re.search(r'\{[\s\S]*\}', text)
            if obj_match:
                try:
                    return json.loads(obj_match.group())
                except json.JSONDecodeError:
                    pass
        return None

    async def autonomous_exploit_loop(self, context: ScanContext, task_description: str, max_steps: int = 5) -> None:
        """
        AI-driven ReAct loop for advanced exploitation using the Cyphex Virtual Subsystem (CVS).
        The agent iteratively generates `curl` commands, executes them, and reads the output.

        FULL VISIBILITY: Every step shows THINK -> ACT -> OBSERVE -> DECISION to the user.
        """
        # -- Banner --
        print(f"\n  {Colors.CYAN}{Colors.BOLD}+{'-' * 60}+{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  [LOOP] AUTONOMOUS EXPLOIT LOOP (ReAct){'':>22}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  Target: {self.target[:48]:<49}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  Goal: {task_description[:50]:<51}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}|  Max Steps: {max_steps:<46}|{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}+{'-' * 60}+{Colors.RESET}\n")

        system_prompt = f"""You are an elite offensive security engineer.
You are tasked with the following exploitation goal: {task_description}

Target URL: {self.target}

You have access to a pure-Python virtual Linux terminal (CVS).
You can ONLY use the following tools:
1. `curl` (Supports -X, -d, -H, -b, -c, -A, --path-as-is, etc.)
2. `grep` (Supports -i, -v, -E, -o)
Example: `curl -s -X GET "http://target/api" -H "Auth: Bearer token" | grep -o "secret=[a-zA-Z0-9]+"`

You must iteratively explore, extract tokens, bypass WAFs, and exploit the target.

RESPOND EXACTLY IN THIS JSON FORMAT:
{{
    "reasoning": "Explain what you are trying to achieve with this command and why.",
    "command": "The exact bash command to execute in the terminal.",
    "found_vuln": true/false,
    "vuln_details": {{"name": "...", "severity": "...", "description": "...", "payload": "..."}} // Only if found_vuln is true
}}

If you have achieved the goal or found a vulnerability, set found_vuln to true and provide details. The loop will then terminate.
If you need more information, generate the next command to gather it.
"""

        conversation_history = "--- Terminal Output History ---\n"

        for step in range(max_steps):
            step_num = step + 1

            # -- Step header --
            print(f"  {Colors.CYAN}{Colors.BOLD}---- STEP {step_num}/{max_steps} ----{Colors.RESET}")

            user_prompt = f"History so far:\n{conversation_history}\n\nWhat is your next command?"

            response_text = await self.call_cerebras(system_prompt, user_prompt)
            data = self._parse_json(response_text)

            if not data or "command" not in data:
                print(f"  {Colors.RED}  [ERR] Failed to parse AI response. Aborting loop.{Colors.RESET}")
                break

            reasoning = data.get('reasoning', 'No reasoning provided')
            command = data['command']

            # -- THINK: Show reasoning --
            print(f"  {Colors.YELLOW}{Colors.BOLD}  [THINK] THINK:{Colors.RESET}")
            for line in reasoning.split('. '):
                if line.strip():
                    print(f"  {Colors.YELLOW}     {line.strip()}.{Colors.RESET}")

            # -- ACT: Show exact command --
            print(f"  {Colors.GREEN}{Colors.BOLD}  [ACT] ACT:{Colors.RESET}")
            print(f"  {Colors.GREEN}     $ {command}{Colors.RESET}")

            # Extract and display payload separately if it's a curl with data
            if '-d ' in command or '--data' in command:
                import re
                data_match = re.search(r'-d\s+["\']([^"\']+)["\']', command)
                if data_match:
                    payload_str = data_match.group(1)
                    print(f"  {Colors.RED}{Colors.BOLD}     [PAYLOAD] PAYLOAD: {payload_str}{Colors.RESET}")

            if '-H ' in command:
                import re
                headers = re.findall(r'-H\s+["\']([^"\']+)["\']', command)
                for h in headers:
                    print(f"  {Colors.DIM}     [HEADER] HEADER: {h}{Colors.RESET}")

            if data.get("found_vuln"):
                vuln_info = data.get("vuln_details", {})
                # -- DECISION: Vuln found --
                print(f"\n  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}  [ALERT] DECISION: VULNERABILITY CONFIRMED  {Colors.RESET}")
                print(f"  {Colors.RED}     Name:     {vuln_info.get('name', 'Unknown')}{Colors.RESET}")
                print(f"  {Colors.RED}     Severity: {vuln_info.get('severity', 'High')}{Colors.RESET}")
                print(f"  {Colors.RED}     Payload:  {vuln_info.get('payload', 'N/A')}{Colors.RESET}")
                print(f"  {Colors.RED}     Detail:   {vuln_info.get('description', '')[:200]}{Colors.RESET}")

                if vuln_info:
                    await self.add_vuln(Vuln(
                        name=vuln_info.get("name", f"Autonomous Vuln - {self.__class__.__name__}"),
                        severity=vuln_info.get("severity", "High"),
                        cvss_score=8.5,
                        endpoint=self.target,
                        payload=vuln_info.get("payload", ""),
                        description=vuln_info.get("description", ""),
                        confirmed=True,
                        fix="Review and remediate based on autonomous findings.",
                    ))
                break

            if not command.strip():
                print(f"  {Colors.DIM}  [ERR] Empty command. Stopping.{Colors.RESET}")
                break

            # Execute command (terminal.run already prints the output)
            result = await self.terminal.run(command)

            # -- OBSERVE: Show response summary --
            stdout_preview = result.stdout[:600] if result.stdout else "(empty)"
            print(f"  {Colors.CYAN}{Colors.BOLD}  [OBSERVE] OBSERVE:{Colors.RESET}")
            print(f"  {Colors.DIM}     Status:  exit_code={result.exit_code} ({len(result.stdout)} bytes){Colors.RESET}")
            # Show first few meaningful lines
            lines = [l for l in stdout_preview.splitlines() if l.strip()][:5]
            for line in lines:
                # Highlight sensitive data in response
                display = line[:120]
                if any(kw in display.lower() for kw in ['password', 'token', 'secret', 'key', 'admin', 'root']):
                    print(f"  {Colors.RED}{Colors.BOLD}     -> {display}{Colors.RESET}")
                else:
                    print(f"  {Colors.DIM}     -> {display}{Colors.RESET}")
            if len(result.stdout) > 600:
                print(f"  {Colors.DIM}     ... ({len(result.stdout) - 600} more bytes){Colors.RESET}")

            # -- DECISION: Continue --
            print(f"  {Colors.BLUE}  [*] DECISION: Need more data -> continuing to step {step_num + 1}{Colors.RESET}")
            print()

            # Append to history
            stdout_hist = result.stdout[:1000] + ("...\n[TRUNCATED]" if len(result.stdout) > 1000 else "")
            stderr_hist = result.stderr[:500]
            conversation_history += f"\n$ {command}\nExit Code: {result.exit_code}\nSTDOUT:\n{stdout_hist}\nSTDERR:\n{stderr_hist}\n"

            # Small delay to avoid API limits
            await asyncio.sleep(2)

        # -- Loop complete --
        print(f"  {Colors.CYAN}{Colors.BOLD}---- EXPLOIT LOOP COMPLETE ({len(self.vulns)} vulns found) ----{Colors.RESET}\n")

