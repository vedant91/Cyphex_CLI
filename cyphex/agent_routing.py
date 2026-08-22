from typing import List, Dict, Any, Set

# Base roles mapping
ROLE_AGENTS = {
    "backend": [
        "DeepSQLiAgent",
        "DeepCMDiAgent",
        "DeepAuthAgent",
        "DeepIDORAgent",
        "DeepSSRFAgent",
        "DeepMassAssignmentAgent",
        "DeepBusinessLogicAgent",
        "DeepPathTraversalAgent"
    ],
    "frontend": [
        "DeepXSSAgent",
        "DeepSSTIAgent"
    ],
    "gateway": [
        "DeepSSRFAgent",
        "DeepPathTraversalAgent",
        "DeepAuthAgent"
    ],
    "rpc": [
        "DeepAuthAgent",
        "DeepBusinessLogicAgent",
        "DeepMassAssignmentAgent"
    ],
    "datastore": [],
    "broker": []
}

# Language specific additions
LANGUAGE_ADDITIONS = {
    "python": ["DeepXXEAgent"],
    "java": ["DeepXXEAgent"],
    "node": ["DeepPromptInjectionAgent"]
}

# Conservative fallback for unknown/low confidence
UNKNOWN_AGENTS = [
    "DeepAuthAgent",
    "DeepIDORAgent",
    "DeepSQLiAgent"
]

def get_agents_for_service(service: Dict[str, Any]) -> List[str]:
    """
    Determine the set of DeepAgent class names to run against a given service.
    """
    # 1. Signature hardcoded override
    override = service.get("agents_override", [])
    if override:
        return override
        
    # 2. Unknown fallback
    if service.get("confidence") == "low":
        return UNKNOWN_AGENTS.copy()
        
    agents: Set[str] = set()
    
    # 3. Roles
    roles = service.get("role", [])
    for role in roles:
        agents.update(ROLE_AGENTS.get(role, []))
        
    # 4. Language
    lang = service.get("language", "unknown")
    agents.update(LANGUAGE_ADDITIONS.get(lang, []))
    
    return sorted(list(agents))
