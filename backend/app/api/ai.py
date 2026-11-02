from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.ai.explanation_service import explanation_service
from app.database.models import Alert, LogEvent, AIExplanation
from app.intelligence.context_builder import context_builder

router = APIRouter()

@router.post("/alerts/{alert_id}/explain")
async def explain_alert(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # Get recent events for this IP
    events_query = select(LogEvent).where(LogEvent.source_ip == alert.source_ip).order_by(LogEvent.event_time.desc()).limit(50)
    events_res = await db.execute(events_query)
    events_db = events_res.scalars().all()
    events_dicts = [{c.name: getattr(e, c.name) for c in e.__table__.columns} for e in events_db]
    
    # Format dates
    for e in events_dicts:
        if e.get("event_time"): e["event_time"] = e["event_time"].isoformat()

    alert_dict = {c.name: getattr(alert, c.name) for c in alert.__table__.columns}
    
    context = await context_builder.build_context(db, alert_dict, events_dicts)
    explanation = await explanation_service.explain_alert(db, alert_id, context)
    return explanation

@router.get("/alerts/{alert_id}/explanation")
async def get_explanation(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(AIExplanation).where(AIExplanation.alert_id == alert_id))
    exp = result.scalars().first()
    if not exp:
        raise HTTPException(status_code=404, detail="Explanation not found")
    return exp
