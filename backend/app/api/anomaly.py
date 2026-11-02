from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any, List

from app.database.database import get_db
from app.core.permissions import get_current_user, get_current_active_admin
from app.schemas.users import User
from app.ml.model_manager import model_manager
from app.database.models import MLModel

router = APIRouter()

@router.get("/status")
async def get_status(current_user: User = Depends(get_current_user)):
    return {
        "active_model_version": model_manager.active_version,
        "is_loaded": model_manager.active_model is not None
    }

@router.post("/train")
async def trigger_training(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_admin)):
    from app.ml.training import train_isolation_forest
    from app.database.models import LogEvent
    
    # Very simple mock dataset extraction for demo purposes
    # In production, we'd window the actual data
    res = await db.execute(select(LogEvent).limit(1000))
    events = res.scalars().all()
    events_dicts = [{c.name: getattr(e, c.name) for c in e.__table__.columns} for e in events]
    
    # Group into pseudo-windows (e.g. 50 events each)
    windows = [events_dicts[i:i+50] for i in range(0, len(events_dicts), 50)]
    
    if not windows:
        raise HTTPException(status_code=400, detail="Not enough data to train")
        
    version = await train_isolation_forest(db, windows)
    return {"message": "Training completed", "version": version}
