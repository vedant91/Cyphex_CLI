"""
CYPHEX DeepAgents — Public exports
13 specialized autonomous vulnerability agents using local Ollama models.
"""
from deepagents.deep_sqli import DeepSQLiAgent
from deepagents.deep_xss import DeepXSSAgent
from deepagents.deep_cmdi import DeepCMDiAgent
from deepagents.deep_auth import DeepAuthAgent
from deepagents.deep_idor import DeepIDORAgent
from deepagents.deep_ssrf import DeepSSRFAgent
from deepagents.deep_ssti import DeepSSTIAgent
from deepagents.deep_path_traversal import DeepPathTraversalAgent
from deepagents.deep_xxe import DeepXXEAgent
from deepagents.deep_business_logic import DeepBusinessLogicAgent
from deepagents.deep_prompt_injection import DeepPromptInjectionAgent
from deepagents.deep_race_condition import DeepRaceConditionAgent
from deepagents.deep_mass_assignment import DeepMassAssignmentAgent

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
    # --- NEW (v4.4) ---
    "DeepPromptInjectionAgent",
    "DeepRaceConditionAgent",
    "DeepMassAssignmentAgent",
]
