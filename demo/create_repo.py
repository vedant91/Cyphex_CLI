"""Create the cyphex-vibemart-demo repo on GitHub and push VibeMart to it."""
import urllib.request
import json
import os
import sys

TOKEN = os.environ.get("GITHUB_TOKEN", "")
if not TOKEN:
    # Try loading from multiple .env locations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)  # cyphex_v3/
    env_candidates = [
        os.path.join(root_dir, ".env"),
        os.path.join(root_dir, "backend", ".env"),
        os.path.join(script_dir, ".env"),
    ]
    for env_path in env_candidates:
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GITHUB_TOKEN="):
                        TOKEN = line.split("=", 1)[1].strip().strip("'\"")
                        break
        if TOKEN:
            break
if not TOKEN:
    print("ERROR: GITHUB_TOKEN not found")
    sys.exit(1)

# Step 1: Create the repo
print("Creating GitHub repo: cyphex-vibemart-demo ...")
data = json.dumps({
    "name": "cyphex-vibemart-demo",
    "description": "VibeMart - Intentionally Vulnerable E-Commerce API for Cyphex Demo",
    "private": False,
    "auto_init": False
}).encode()

req = urllib.request.Request(
    "https://api.github.com/user/repos",
    data=data,
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }
)

try:
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read().decode())
    print(f"OK: Created {result['html_url']}")
    print(f"Clone URL: {result['clone_url']}")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    if "already exists" in body:
        print("Repo already exists, continuing...")
    else:
        print(f"Error {e.code}: {body}")
        sys.exit(1)

# Step 2: Get the authenticated user's username
req2 = urllib.request.Request(
    "https://api.github.com/user",
    headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"}
)
user_resp = urllib.request.urlopen(req2)
username = json.loads(user_resp.read().decode())["login"]
print(f"GitHub user: {username}")
print(f"Full URL: https://github.com/{username}/cyphex-vibemart-demo")
