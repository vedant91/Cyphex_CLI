import os
import yaml
import pytest
from cyphex.compose_synth import synthesize_compose

def test_synthesize_compose_no_existing_dockerfile(tmp_path):
    # Setup
    backend_dir = tmp_path / "backend"
    backend_dir.mkdir()
    
    manifest = {
        "services": {
            "api": {
                "path": "backend",
                "language": "python",
                "port": 5000
            }
        }
    }
    
    # Run
    compose_path = synthesize_compose(str(tmp_path), manifest)
    
    # Verify docker-compose.sandbox.yml
    assert os.path.exists(compose_path)
    with open(compose_path, "r") as f:
        compose = yaml.safe_load(f)
        
    assert compose["version"] == "3.8"
    assert "cyphex-net" in compose["networks"]
    
    api_srv = compose["services"]["api"]
    assert api_srv["build"]["context"] == "backend"
    assert api_srv["build"]["dockerfile"] == "Dockerfile.cyphex"
    assert api_srv["ports"] == ["127.0.0.1:0:5000"]
    assert api_srv["cap_drop"] == ["ALL"]
    assert api_srv["security_opt"] == ["no-new-privileges:true"]
    assert api_srv["pids_limit"] == 200
    assert api_srv["deploy"]["resources"]["limits"]["memory"] == "512m"
    
    # Verify generated Dockerfile.cyphex
    dockerfile_path = backend_dir / "Dockerfile.cyphex"
    assert os.path.exists(dockerfile_path)
    content = dockerfile_path.read_text()
    assert "FROM python:3.12-slim" in content
    assert "EXPOSE 5000" in content

def test_synthesize_compose_with_existing_dockerfile(tmp_path):
    # Setup
    frontend_dir = tmp_path / "frontend"
    frontend_dir.mkdir()
    
    existing_dockerfile = frontend_dir / "Dockerfile"
    existing_dockerfile.write_text("FROM custom-node:latest\nCMD npm run dev")
    
    manifest = {
        "services": {
            "web": {
                "path": "frontend",
                "language": "node",
                "port": 3000
            }
        }
    }
    
    # Run
    compose_path = synthesize_compose(str(tmp_path), manifest)
    
    # Verify docker-compose.sandbox.yml
    with open(compose_path, "r") as f:
        compose = yaml.safe_load(f)
        
    web_srv = compose["services"]["web"]
    assert web_srv["build"]["dockerfile"] == "Dockerfile"
    
    # Verify no Dockerfile.cyphex was created
    assert not os.path.exists(frontend_dir / "Dockerfile.cyphex")
    
    # Verify existing is untouched
    assert existing_dockerfile.read_text() == "FROM custom-node:latest\nCMD npm run dev"
