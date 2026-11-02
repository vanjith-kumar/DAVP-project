from pydantic import BaseModel
from typing import List, Optional

class AIExplanationResponse(BaseModel):
    summary: str
    possible_attack_type: str
    confidence: str
    investigation_steps: List[str]
    # Fields from mock fallback
    evidence_summary: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    # Fields from real Ollama (kept for backwards compat)
    why_it_matters: Optional[str] = None
    evidence: Optional[List[str]] = None
    uncertainty: Optional[str] = None
    suggested_actions: Optional[List[str]] = None
