import os
import json
import pytest
import tempfile
import yaml
from cyphex.service_detection import detect_services, _match_signature

def test_single_stack_detection(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "test"}')
    (tmp_path / "vite.config.js").write_text('// vite config')
    
    result = detect_services(str(tmp_path))
    assert len(result["services"]) == 1
    
    app = list(result["services"].values())[0]
    assert app["stack"] == "react-vite"
    assert app["role"] == ["frontend"]
    assert app["language"] == "node"
    assert app["confidence"] == "high"

def test_multi_stack_detection_with_datastores(tmp_path):
    # Backend
    backend_dir = tmp_path / "backend"
    backend_dir.mkdir()
    (backend_dir / "requirements.txt").write_text('fastapi==0.100.0')
    
    # Frontend
    frontend_dir = tmp_path / "frontend"
    frontend_dir.mkdir()
    (frontend_dir / "package.json").write_text('{}')
    (frontend_dir / "next.config.js").write_text('{}')
    
    # Datastore
    compose_content = {
        "services": {
            "db": {
                "image": "postgres:15"
            }
        }
    }
    (tmp_path / "docker-compose.yml").write_text(yaml.dump(compose_content))
    
    result = detect_services(str(tmp_path))
    
    assert len(result["services"]) == 2
    
    backend = result["services"]["backend"]
    assert backend["stack"] == "fastapi"
    assert backend["role"] == ["backend"]
    
    frontend = result["services"]["frontend"]
    assert frontend["stack"] == "nextjs"
    assert frontend["role"] == ["frontend", "backend"]
    
    assert len(result["datastores"]) == 1
    assert result["datastores"][0]["name"] == "db"
    assert result["datastores"][0]["role"] == ["datastore"]

def test_unknown_stack_fallback(tmp_path):
    (tmp_path / "manage.py").write_text('# Just python')
    # Actually django has manage.py, let's test a generic one
    (tmp_path / "package.json").write_text('{"name": "unknown-node"}')
    
    result = detect_services(str(tmp_path))
    # It might match node-generic or unknown. node-generic is better.
    app = list(result["services"].values())[0]
    assert app["language"] == "node"
    
def test_port_collision_resolution(tmp_path):
    (tmp_path / "app1").mkdir()
    (tmp_path / "app1" / "package.json").write_text('{}')
    (tmp_path / "app1" / "nest-cli.json").write_text('{}') # port 3000
    
    (tmp_path / "app2").mkdir()
    (tmp_path / "app2" / "package.json").write_text('{}')
    (tmp_path / "app2" / "next.config.js").write_text('{}') # port 3000
    
    result = detect_services(str(tmp_path))
    assert len(result["services"]) == 2
    
    ports = [s["port"] for s in result["services"].values()]
    assert 3000 in ports
    assert 3001 in ports

def test_monorepo_non_descent(tmp_path):
    backend_dir = tmp_path / "backend"
    backend_dir.mkdir()
    (backend_dir / "package.json").write_text('{}')
    
    # Should not descend into node_modules or claimed roots' subfolders
    sub_dir = backend_dir / "subapp"
    sub_dir.mkdir()
    (sub_dir / "requirements.txt").write_text('flask')
    
    result = detect_services(str(tmp_path))
    assert len(result["services"]) == 1
    assert "backend" in result["services"]
    assert "backend-subapp" not in result["services"]
