from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime

class DetectionRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    rule_type: str
    severity: str
    enabled: bool
    configuration: Dict[str, Any]
    
    model_config = ConfigDict(from_attributes=True)
