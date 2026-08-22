"""
CYPHEX — CLI Entry Point

Usage:
  python main.py --target http://localhost:3000
  python main.py --target http://localhost:3000 --cerebras-key <key>
  python main.py --target http://localhost:3000 --output report.json

This is the terminal-first interface. No frontend needed.
The pipeline executes all 10 agents and prints results to your terminal.
"""

import asyncio
import argparse
import io
import json
import os
import sys
import uuid
from datetime import datetime

# Force UTF-8 output on Windows
if os.name == "nt":
    os.system("")  # Enables ANSI escape codes on Windows
    os.environ.setdefault("PYTHONUTF8", "1")

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Repo root — needed so scan_orchestrator's `from scoring import ...` (the
# single source of truth for the security posture score, shared with the
# CLI's terminal_ui.py/cli_engine.py) resolves regardless of launch cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scan_orchestrator import ScanOrchestrator
from agents.terminal import Colors
from config import config


def parse_args():
    parser = argparse.ArgumentParser(
        description="CYPHEX — Multi-Agent Exploitation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target http://localhost:3000
  python main.py --target http://localhost:3000 --output report.json
  python main.py --target http://vulncorp.local --cerebras-key csk-xxx
        """,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to scan (e.g., http://localhost:3000)",
    )
    parser.add_argument(
        "--cerebras-key", "-k",
        default="",
        help="Cerebras API key (defaults to built-in key)",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output file for JSON report (optional)",
    )
    parser.add_argument(
        "--scan-id",
        default="",
        help="Custom scan ID (auto-generated if not provided)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Scan timeout in seconds (default: 1800 = 30 min)",
    )
    return parser.parse_args()


async def main():
    args = parse_args()

    # Normalize target URL
    target = args.target.strip().rstrip("/")
    if not target.startswith("http"):
        target = f"http://{target}"

    # Generate scan ID
    scan_id = args.scan_id or f"scan_{uuid.uuid4().hex[:8]}"

    # Set timeout
    config.SCAN_TIMEOUT_SECONDS = args.timeout

    # Override Cerebras key if provided
    if args.cerebras_key:
        config.CEREBRAS_API_KEY = args.cerebras_key

    # Run the scan
    orchestrator = ScanOrchestrator()

    try:
        report = await asyncio.wait_for(
            orchestrator.run_scan(scan_id, target, config.CEREBRAS_API_KEY),
            timeout=config.SCAN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        print(f"\n{Colors.RED}Scan timed out after {config.SCAN_TIMEOUT_SECONDS}s{Colors.RESET}")
        report = {"error": "timeout"}
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
        report = {"error": "interrupted"}

    # Save report
    if args.output or True:  # Always save
        output_file = args.output or os.path.join(
            config.WORKING_DIR, scan_id, "report.json"
        )
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(
            f"  {Colors.GREEN}Report saved to: {output_file}{Colors.RESET}\n"
        )

    return report


if __name__ == "__main__":
    asyncio.run(main())
