class CouncilCallError(Exception):
    """Model returned non-JSON or timed out."""
    pass

class ConsensusError(Exception):
    """Council could not reach minimum consensus after round 2."""
    pass

class VRAMError(Exception):
    """Model cannot be loaded within VRAM budget."""
    pass

class ModelNotFoundError(Exception):
    """Ollama model not pulled. Direct user to run ollama pull."""
    pass
