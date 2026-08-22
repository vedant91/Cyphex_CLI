import pytest
from cyphex.agent_routing import get_agents_for_service

def test_backend_python():
    service = {
        "role": ["backend"],
        "language": "python",
        "confidence": "high"
    }
    agents = get_agents_for_service(service)
    assert "DeepSQLiAgent" in agents
    assert "DeepXXEAgent" in agents
    assert "DeepPromptInjectionAgent" not in agents
    assert "DeepXSSAgent" not in agents

def test_frontend_backend_node():
    service = {
        "role": ["frontend", "backend"],
        "language": "node",
        "confidence": "high"
    }
    agents = get_agents_for_service(service)
    assert "DeepXSSAgent" in agents
    assert "DeepSQLiAgent" in agents
    assert "DeepPromptInjectionAgent" in agents
    assert "DeepXXEAgent" not in agents

def test_rpc_go():
    service = {
        "role": ["rpc"],
        "language": "go",
        "confidence": "high"
    }
    agents = get_agents_for_service(service)
    assert "DeepAuthAgent" in agents
    assert "DeepSQLiAgent" not in agents

def test_unknown_fallback():
    service = {
        "role": ["backend"],
        "language": "php",
        "confidence": "low"
    }
    agents = get_agents_for_service(service)
    assert len(agents) == 3
    assert "DeepAuthAgent" in agents
    assert "DeepIDORAgent" in agents
    assert "DeepSQLiAgent" in agents

def test_override():
    service = {
        "role": ["backend"],
        "language": "python",
        "confidence": "high",
        "agents_override": ["CustomAgent"]
    }
    agents = get_agents_for_service(service)
    assert agents == ["CustomAgent"]
