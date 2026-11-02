from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class LogIngest(BaseModel):
    message: str
    source_id: Optional[int] = None

class LogBatchIngest(BaseModel):
    messages: List[str]
    source_id: Optional[int] = None

class LogEventResponse(BaseModel):
    id: int
    event_time: datetime
    source_ip: Optional[str]
    username: Optional[str]
    event_type: Optional[str]
    severity: Optional[str]
    message: Optional[str]
    parse_status: str
    
    model_config = ConfigDict(from_attributes=True)
