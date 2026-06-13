import urllib.request
import json
import sys

def simulate_push():
    url = "http://127.0.0.1:3005/api/github/webhook"
    
    payload = {
        "repository": {
            "html_url": "https://github.com/VishalMache/target_3",
            "clone_url": "https://github.com/VishalMache/target_3.git"
        },
        "ref": "refs/heads/main",
        "pusher": {
            "name": "Vedant (Local Simulator)"
        }
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data)
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-GitHub-Event', 'push')
    
    print("Sending simulated GitHub push to CYPHEX Webhook...")
    try:
        response = urllib.request.urlopen(req)
        response_data = json.loads(response.read().decode('utf-8'))
        print("Response from CYPHEX:")
        print(json.dumps(response_data, indent=2))
        print("\nCheck your terminal running the 'github-hook' to see it working!")
    except Exception as e:
        print(f"❌ Failed to connect to webhook: {e}")
        print("Make sure you are running 'python cyphex_cli.py github-hook --port 3005' in another terminal.")

if __name__ == "__main__":
    simulate_push()
