import shlex
import argparse
import httpx
import asyncio
import re
import urllib.parse
from typing import Dict, Any

async def execute_cvs_command(command: str, cwd: str, timeout: int) -> Dict[str, Any]:
    """
    Tries to execute a shell command purely in Python (Cyphex Virtual Subsystem).
    Returns dict with 'handled', 'stdout', 'stderr', 'exit_code'.
    If 'handled' is False, the caller should fall back to real subprocess.
    """
    # Quick check if it's a supported command. Currently emulating 'curl'.
    cmd_stripped = command.strip()
    if not (cmd_stripped.startswith("curl ") or cmd_stripped.startswith("curl.exe ")):
        return {"handled": False}
    
    # Basic pipe splitting.
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Unmatched quotes -> fallback to native shell
        return {"handled": False}
        
    pipe_index = -1
    if "|" in tokens:
        pipe_index = tokens.index("|")
        
    curl_tokens = tokens[:pipe_index] if pipe_index != -1 else tokens
    post_pipe_tokens = tokens[pipe_index+1:] if pipe_index != -1 else []
    
    if not curl_tokens or curl_tokens[0] not in ("curl", "curl.exe"):
        return {"handled": False}
        
    # Supported pipe utilities
    if post_pipe_tokens and post_pipe_tokens[0] not in ("grep", "cat"):
        return {"handled": False}

    # Parse curl arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('url', nargs='?')
    parser.add_argument('-X', '--request', default='GET')
    parser.add_argument('-d', '--data', default=None)
    parser.add_argument('-H', '--header', action='append', default=[])
    parser.add_argument('-s', '--silent', action='store_true')
    parser.add_argument('-I', '--head', action='store_true')
    parser.add_argument('-k', '--insecure', action='store_true')
    parser.add_argument('-L', '--location', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-b', '--cookie', default=None)
    parser.add_argument('-c', '--cookie-jar', default=None)
    parser.add_argument('-i', '--include', action='store_true')
    parser.add_argument('-A', '--user-agent', default=None)
    parser.add_argument('--path-as-is', action='store_true')
    
    try:
        args, unknown = parser.parse_known_args(curl_tokens[1:])
    except Exception:
        return {"handled": False}
        
    if not args.url:
        if unknown and not unknown[0].startswith('-'):
            args.url = unknown[0]
        else:
            return {"handled": False}
            
    # Execute with httpx
    headers = {}
    for h in args.header:
        if ':' in h:
            k, v = h.split(':', 1)
            headers[k.strip()] = v.strip()
            
    if args.cookie:
        headers["Cookie"] = args.cookie
        
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
            
    method = "HEAD" if args.head else args.request.upper()
    
    stdout = ""
    stderr = ""
    exit_code = 0
    
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=args.location, timeout=timeout) as client:
            req = client.build_request(method, args.url, headers=headers, content=args.data)
            resp = await client.send(req)
            
            headers_text = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\n"
            for k, v in resp.headers.items():
                headers_text += f"{k}: {v}\n"
            headers_text += "\n"
                
            if args.head:
                stdout = headers_text
            else:
                stdout = resp.text
                if args.include:
                    stdout = headers_text + stdout
                    
                if args.verbose:
                    stderr = f"> {method} {args.url}\n< HTTP {resp.status_code}\n"
                    
    except Exception as e:
        stderr = f"curl: (6) Could not resolve host: {str(e)}"
        exit_code = 6

    # Handle grep pipe
    if post_pipe_tokens and exit_code == 0:
        if post_pipe_tokens[0] == "grep":
            grep_parser = argparse.ArgumentParser(add_help=False)
            grep_parser.add_argument('-i', '--ignore-case', action='store_true')
            grep_parser.add_argument('-v', '--invert-match', action='store_true')
            grep_parser.add_argument('-E', '--extended-regexp', action='store_true')
            grep_parser.add_argument('-o', '--only-matching', action='store_true')
            grep_parser.add_argument('pattern', nargs='?')
            
            try:
                grep_args, unknown_grep = grep_parser.parse_known_args(post_pipe_tokens[1:])
                pattern = grep_args.pattern or (unknown_grep[0] if unknown_grep else None)
                flags = re.IGNORECASE if grep_args.ignore_case else 0
                
                if not pattern:
                    return {"handled": False}
                
                # Simple line-by-line grep
                matched_lines = []
                for line in stdout.splitlines():
                    try:
                        if grep_args.only_matching:
                            # Extract all occurrences on the line
                            for match in re.finditer(pattern, line, flags):
                                matched_lines.append(match.group(0))
                        else:
                            match = re.search(pattern, line, flags)
                            if (match and not grep_args.invert_match) or (not match and grep_args.invert_match):
                                matched_lines.append(line)
                    except re.error:
                        pass
                stdout = "\n".join(matched_lines)
                if not matched_lines:
                    exit_code = 1
            except Exception:
                return {"handled": False}
                
    return {
        "handled": True,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code
    }
