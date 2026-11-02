from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class AlertResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    detection_type: str
    source_ip: Optional[str]
    username: Optional[str]
    event_count: int
    created_at: datetime
    last_seen_at: Optional[datetime]
    description: Optional[str] = None
    risk_score: Optional[float] = None
    
    model_config = ConfigDict(from_attributes=True)

class AlertUpdate(BaseModel):
    status: Optional[str] = None
