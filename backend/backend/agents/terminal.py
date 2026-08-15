"""
CYPHEX — Terminal Engine (CORE)

Gives each agent REAL terminal access. Every command is executed via
asyncio subprocess, with full stdout/stderr/exit_code/duration tracking.

On Windows: uses PowerShell
On Linux: uses /bin/bash

Every command + output is logged and streamed in real-time.
"""

import asyncio
import os
import sys
import time
from datetime import datetime
from typing import Any, Callable, Optional

from models.agent_result import TerminalOutput
from config import config
from live_log_queue import log_queue

# Force UTF-8 output on Windows
if os.name == 'nt':
    os.environ.setdefault("PYTHONUTF8", "1")


# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


# Agent color mapping
AGENT_COLORS = {
    "ReconAgent": Colors.CYAN,
    "CrawlerAgent": Colors.MAGENTA,
    "SQLiAgent": Colors.RED,
    "XSSAgent": Colors.YELLOW,
    "AuthAgent": Colors.BLUE,
    "CMDiAgent": Colors.RED,
    "LFIAgent": Colors.YELLOW,
    "LogicAgent": Colors.MAGENTA,
    "CerebrasAnalysisAgent": Colors.CYAN,
    "PatchAgent": Colors.GREEN,
}


class AgentTerminal:
    """
    Gives each agent a real isolated terminal session.
    Every command is logged with full stdout/stderr/exit_code/duration.
    """

    def __init__(
        self,
        agent_name: str,
        target_url: str,
        scan_id: str,
    ):
        self.agent_name = agent_name
        self.target = target_url
        self.scan_id = scan_id
        self.command_history: list[TerminalOutput] = []
        self.color = AGENT_COLORS.get(agent_name, Colors.WHITE)

        # Working directory for this agent
        self.working_dir = os.path.join(
            config.WORKING_DIR, scan_id, agent_name
        )
        os.makedirs(self.working_dir, exist_ok=True)

    def _print_command(self, command: str):
        """Print command being executed to console."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        agent_tag = f"{self.color}{Colors.BOLD}[{self.agent_name}]{Colors.RESET}"
        print(
            f"  {Colors.DIM}{timestamp}{Colors.RESET} "
            f"{agent_tag} "
            f"{Colors.GREEN}${Colors.RESET} {command}"
        )

    def _safe_print(self, text: str):
        """Print text safely, handling encoding errors on Windows."""
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode('ascii', errors='replace').decode('ascii'))

    def _print_output(self, line: str, stream: str = "stdout"):
        """Print a single line of output."""
        agent_tag = f"{self.color}|{Colors.RESET}"
        if stream == "stderr":
            self._safe_print(f"  {'':>8} {agent_tag} {Colors.RED}{line}{Colors.RESET}")
        else:
            # Highlight interesting patterns
            if any(kw in line.lower() for kw in [
                "vulnerable", "injection", "exploit", "confirmed",
                "critical", "found", "root:", "uid=", "password"
            ]):
                self._safe_print(f"  {'':>8} {agent_tag} {Colors.RED}{Colors.BOLD}{line}{Colors.RESET}")
            elif any(kw in line.lower() for kw in ["success", "complete", "done", "ok"]):
                self._safe_print(f"  {'':>8} {agent_tag} {Colors.GREEN}{line}{Colors.RESET}")
            else:
                self._safe_print(f"  {'':>8} {agent_tag} {Colors.GRAY}{line}{Colors.RESET}")

    async def run(self, command: str, timeout: int = 60) -> TerminalOutput:
        """
        Execute a real terminal command.
        Streams output line by line to console.
        Returns full TerminalOutput with stdout/stderr/exit_code/duration.
        """
        # On Windows, PowerShell aliases 'curl' to Invoke-WebRequest.
        # Replace 'curl' with 'curl.exe' and use cmd.exe shell.
        if config.IS_WINDOWS:
            if command.startswith("curl ") or " curl " in command:
                command = command.replace("curl ", "curl.exe ", 1)

        self._print_command(command)
        start_time = time.time()

        try:
            # --- CYPLEX VIRTUAL SUBSYSTEM (CVS) INTERCEPTION ---
            # Attempt to execute the command natively via pure Python first
            from backend.backend.agents.cvs_shell import execute_cvs_command
            cvs_result = await execute_cvs_command(command, self.working_dir, timeout)
            if cvs_result.get("handled", False):
                duration_ms = (time.time() - start_time) * 1000
                stdout_text = cvs_result.get("stdout", "")
                stderr_text = cvs_result.get("stderr", "")
                
                for line in stdout_text.splitlines():
                    self._print_output(line, "stdout")
                    await log_queue.put({
                        "type": "terminal_log",
                        "agent_name": self.agent_name,
                        "command": command,
                        "stdout": line,
                        "success": True
                    })
                for line in stderr_text.splitlines():
                    self._print_output(line, "stderr")
                    
                result = TerminalOutput(
                    command=command,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    exit_code=cvs_result.get("exit_code", 0),
                    duration_ms=round(duration_ms, 2),
                    timestamp=datetime.now(),
                )
                self.command_history.append(result)
                return result
            # ---------------------------------------------------

            if config.IS_WINDOWS:
                # Windows + Uvicorn: asyncio.create_subprocess_shell raises
                # NotImplementedError because Uvicorn forces SelectorEventLoop.
                # Use threaded subprocess.Popen as a reliable fallback.
                return await self._run_windows(command, timeout, start_time)
            else:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.working_dir,
                    executable="/bin/bash",
                )

            # Stream stdout line by line
            stdout_lines = []
            stderr_lines = []

            async def read_stdout():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").rstrip()
                    stdout_lines.append(decoded)
                    self._print_output(decoded, "stdout")
                    await log_queue.put({
                        "type": "terminal_log",
                        "agent_name": self.agent_name,
                        "command": command,
                        "stdout": decoded,
                        "success": True
                    })

            async def read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").rstrip()
                    stderr_lines.append(decoded)
                    self._print_output(decoded, "stderr")

            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout(), read_stderr(), proc.wait()),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                stderr_lines.append(f"[CYPHEX] Command timed out after {timeout}s")
                self._print_output(f"[!] Command timed out after {timeout}s", "stderr")

            duration_ms = (time.time() - start_time) * 1000
            result = TerminalOutput(
                command=command,
                stdout="\n".join(stdout_lines),
                stderr="\n".join(stderr_lines),
                exit_code=proc.returncode if proc.returncode is not None else -1,
                duration_ms=round(duration_ms, 2),
                timestamp=datetime.now(),
            )
            self.command_history.append(result)
            return result

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_msg = f"[CYPHEX] Execution error: {str(e)}"
            self._print_output(error_msg, "stderr")
            result = TerminalOutput(
                command=command,
                stdout="",
                stderr=error_msg,
                exit_code=-1,
                duration_ms=round(duration_ms, 2),
                timestamp=datetime.now(),
            )
            self.command_history.append(result)
            return result

    async def _run_windows(self, command: str, timeout: int, start_time: float) -> TerminalOutput:
        """
        Windows fallback: run commands via subprocess.Popen in a thread.
        Uvicorn on Windows uses SelectorEventLoop which does NOT support
        asyncio.create_subprocess_shell (raises NotImplementedError).
        """
        import subprocess

        def _sync_exec():
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self.working_dir,
                    shell=True,
                )
                stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
                return {
                    "stdout": stdout_bytes.decode(errors="replace"),
                    "stderr": stderr_bytes.decode(errors="replace"),
                    "exit_code": proc.returncode,
                    "timed_out": False,
                }
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                return {
                    "stdout": "",
                    "stderr": f"[CYPHEX] Command timed out after {timeout}s",
                    "exit_code": -1,
                    "timed_out": True,
                }

        raw = await asyncio.to_thread(_sync_exec)
        duration_ms = (time.time() - start_time) * 1000

        stdout_text = raw["stdout"]
        stderr_text = raw["stderr"]

        for line in stdout_text.splitlines():
            self._print_output(line, "stdout")
            await log_queue.put({
                "type": "terminal_log",
                "agent_name": self.agent_name,
                "command": command,
                "stdout": line,
                "success": True,
            })
        for line in stderr_text.splitlines():
            self._print_output(line, "stderr")

        result = TerminalOutput(
            command=command,
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=raw["exit_code"],
            duration_ms=round(duration_ms, 2),
            timestamp=datetime.now(),
        )
        self.command_history.append(result)
        return result

    async def run_and_parse(
        self, command: str, parser_fn: Callable, timeout: int = 60
    ) -> Any:
        """Run a command and parse its output with the provided function."""
        output = await self.run(command, timeout=timeout)
        try:
            return parser_fn(output.stdout)
        except Exception as e:
            self._print_output(f"Parse error: {e}", "stderr")
            return None

    async def run_python(self, script: str, timeout: int = 30) -> TerminalOutput:
        """Run an inline Python script."""
        # Escape for command line
        escaped = script.replace('"', '\\"')
        if config.IS_WINDOWS:
            return await self.run(f'python -c "{escaped}"', timeout=timeout)
        else:
            return await self.run(f'python3 -c "{escaped}"', timeout=timeout)

    async def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available on the system."""
        if config.IS_WINDOWS:
            result = await self.run(
                f"where {tool_name} 2>NUL", timeout=5
            )
        else:
            result = await self.run(
                f"which {tool_name} 2>/dev/null", timeout=5
            )
        return result.success

    def get_history(self) -> list[dict]:
        """Get full command history as dicts."""
        return [cmd.to_dict() for cmd in self.command_history]
