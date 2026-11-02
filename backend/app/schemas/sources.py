from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime

class LogSourceBase(BaseModel):
    name: str
    source_type: str
    description: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None
    enabled: bool = True

class LogSourceCreate(LogSourceBase):
    pass

class LogSourceUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None

class LogSourceResponse(LogSourceBase):
    id: int
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
