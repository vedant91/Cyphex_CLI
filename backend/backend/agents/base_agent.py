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
import shlex
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

    # Binaries the autonomous exploit loop is allowed to execute. This must
    # match what the system prompt in `autonomous_exploit_loop` tells the
    # model it can use — the model's output is untrusted (it can be steered
    # by attacker-controlled content reflected back from the scanned
    # target, i.e. indirect prompt injection) so it is enforced here too.
    ALLOWED_EXPLOIT_COMMANDS = {"curl", "grep"}

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
            f"  🚨 VULN FOUND: [{vuln.severity}] {vuln.name} "
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

        Fallback chain: groq → ollama → empty string
        """
        mode = config.AI_BACKEND_MODE

        if mode == "groq":
            result = await self._call_groq(system_prompt, user_prompt, max_retries)
            if result:
                return result
            # Auto-fallback to Ollama if Groq fails
            await self.log("Groq failed → falling back to local Ollama", "warning")
            return await self._call_ollama(system_prompt, user_prompt, max_retries=2)

        elif mode == "local":
            result = await self._call_ollama(system_prompt, user_prompt, max_retries)
            if result:
                return result
            # Auto-fallback to Groq if Ollama fails and key is available
            if config.GROQ_API_KEY:
                await self.log("Ollama failed → falling back to Groq cloud", "warning")
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
                        await self.log("Groq AI response received ✓", "success")
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
                        await self.log("Local AI response received ✓", "success")
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

    def _validate_exploit_command(self, cmd: str) -> tuple[bool, str]:
        """
        Enforce the curl/grep-only allowlist promised to the model in the
        autonomous exploit loop's system prompt.

        The command string is LLM-generated and the conversation feeding it
        includes raw content reflected back from the scanned target, so a
        malicious/compromised target can attempt indirect prompt injection
        to get arbitrary shell commands executed on the CYPHEX host. Never
        trust `cmd` — parse it and check every pipeline/command stage's
        binary against ALLOWED_EXPLOIT_COMMANDS before it is ever handed to
        the real shell.

        Note: plain `shlex.split` is a POSIX-ish *word* tokenizer, not a
        full shell grammar — it does NOT treat `;`, `&&`, `||`, `&`, `|` as
        operators when they aren't surrounded by whitespace (e.g.
        `"curl x;rm -rf /"` would come back as a single token `"x;rm"`,
        silently hiding the second command from a naive argv[0] check).
        We instead use `shlex.shlex(..., punctuation_chars=True)`, which
        always splits those shell control-operator characters into their
        own tokens — matching real bash's tokenization — while still
        respecting quoting. Every resulting command stage's binary is then
        checked against ALLOWED_EXPLOIT_COMMANDS. We also reject any token
        containing `$(` or a backtick (command/process substitution),
        since real bash — which `terminal.run()` ultimately shells out to
        — evaluates those regardless of quoting, and they are never needed
        for the curl/grep usage the system prompt describes. Together this
        closes the two main ways a single allowlisted `argv[0]` check
        could otherwise be bypassed to run a second, non-allowlisted
        command.

        Returns (is_valid, reason). If not valid, `reason` explains why so
        the caller can log it and skip the step instead of crashing.
        """
        try:
            lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError as e:
            return False, f"could not parse command ({e})"

        if not tokens:
            return False, "empty command"

        for tok in tokens:
            if "$(" in tok or "`" in tok:
                return False, (
                    f"token {tok!r} contains command/process substitution, "
                    f"which is never required for curl/grep"
                )

        # Split on shell control-operator tokens so `curl ... | grep ...`,
        # `curl ...; rm -rf /`, `curl ... && evil`, etc. are all validated
        # stage-by-stage rather than only checking the first command.
        CONTROL_OPERATORS = {"|", ";", "&&", "||", "&"}
        stages: list[list[str]] = [[]]
        for tok in tokens:
            if tok in CONTROL_OPERATORS:
                stages.append([])
            else:
                stages[-1].append(tok)

        for stage in stages:
            if not stage:
                return False, "empty command stage (e.g. trailing/leading operator)"
            binary = stage[0]
            if binary not in self.ALLOWED_EXPLOIT_COMMANDS:
                return False, (
                    f"'{binary}' is not in the allowlist "
                    f"{sorted(self.ALLOWED_EXPLOIT_COMMANDS)}"
                )

        return True, ""

    async def autonomous_exploit_loop(self, context: ScanContext, task_description: str, max_steps: int = 5) -> None:
        """
        AI-driven ReAct loop for advanced exploitation using the Cyphex Virtual Subsystem (CVS).
        The agent iteratively generates `curl` commands, executes them, and reads the output.
        """
        await self.log(f"Starting Autonomous Exploit Loop: {task_description}", "warning")
        
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
            await self.log(f"Autonomous Loop Step {step+1}/{max_steps}...", "info")
            user_prompt = f"History so far:\n{conversation_history}\n\nWhat is your next command?"
            
            response_text = await self.call_cerebras(system_prompt, user_prompt)
            data = self._parse_json(response_text)
            
            if not data or "command" not in data:
                await self.log("Failed to parse AI response. Aborting loop.", "danger")
                break
                
            await self.log(f"Reasoning: {data.get('reasoning', '')}", "info")
            
            if data.get("found_vuln"):
                vuln_info = data.get("vuln_details", {})
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
                
            cmd = data["command"]
            if not cmd.strip():
                break

            # Enforce the curl/grep-only allowlist before touching the real
            # shell — refuse and skip rather than crash the whole scan.
            is_valid, reason = self._validate_exploit_command(cmd)
            if not is_valid:
                await self.log(
                    f"Refusing to execute disallowed command ({reason}): {cmd!r}",
                    "danger",
                )
                conversation_history += (
                    f"\n$ {cmd}\n[CYPHEX] Command rejected by allowlist — {reason}. "
                    f"Only {sorted(self.ALLOWED_EXPLOIT_COMMANDS)} are permitted.\n"
                )
                await asyncio.sleep(1)
                continue

            # Execute command
            result = await self.terminal.run(cmd)
            
            # Append to history
            stdout_preview = result.stdout[:1000] + ("...\n[TRUNCATED]" if len(result.stdout) > 1000 else "")
            stderr_preview = result.stderr[:500]
            
            conversation_history += f"\n$ {cmd}\nExit Code: {result.exit_code}\nSTDOUT:\n{stdout_preview}\nSTDERR:\n{stderr_preview}\n"
            
            # Small delay to avoid API limits
            await asyncio.sleep(2)
            
        await self.log("Autonomous Exploit Loop Finished.", "info")
