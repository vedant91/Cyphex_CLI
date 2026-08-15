"""
CYPHEX DeepAgents — Public exports
13 specialized autonomous vulnerability agents using local Ollama models.

10 core agents + 3 merged from update_y1 (prompt injection / OWASP LLM01,
race-condition / TOCTOU, and mass assignment / CWE-915).
"""
from backend.deepagents.deep_sqli import DeepSQLiAgent
from backend.deepagents.deep_xss import DeepXSSAgent
from backend.deepagents.deep_cmdi import DeepCMDiAgent
from backend.deepagents.deep_auth import DeepAuthAgent
from backend.deepagents.deep_idor import DeepIDORAgent
from backend.deepagents.deep_ssrf import DeepSSRFAgent
from backend.deepagents.deep_ssti import DeepSSTIAgent
from backend.deepagents.deep_path_traversal import DeepPathTraversalAgent
from backend.deepagents.deep_xxe import DeepXXEAgent
from backend.deepagents.deep_business_logic import DeepBusinessLogicAgent
from backend.deepagents.deep_prompt_injection import DeepPromptInjectionAgent
from backend.deepagents.deep_race_condition import DeepRaceConditionAgent
from backend.deepagents.deep_mass_assignment import DeepMassAssignmentAgent

__all__ = [
    "DeepSQLiAgent",
    "DeepXSSAgent",
    "DeepCMDiAgent",
    "DeepAuthAgent",
    "DeepIDORAgent",
    "DeepSSRFAgent",
    "DeepSSTIAgent",
    "DeepPathTraversalAgent",
    "DeepXXEAgent",
    "DeepBusinessLogicAgent",
    "DeepPromptInjectionAgent",
    "DeepRaceConditionAgent",
    "DeepMassAssignmentAgent",
]
