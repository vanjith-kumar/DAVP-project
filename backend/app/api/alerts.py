from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.schemas.alerts import AlertResponse, AlertUpdate
from app.services.alert_service import get_alerts, get_alert, update_alert_status

router = APIRouter()

@router.get("/", response_model=List[AlertResponse])
async def read_alerts(skip: int = 0, limit: int = 50, status: Optional[str] = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await get_alerts(db, skip=skip, limit=limit, status=status)

@router.get("/{alert_id}", response_model=AlertResponse)
async def read_alert(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    alert = await get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/{alert_id}/{action}", response_model=AlertResponse)
async def perform_alert_action(alert_id: int, action: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    valid_actions = {
        "acknowledge": "ACKNOWLEDGED",
        "resolve": "RESOLVED",
        "false-positive": "FALSE_POSITIVE",
        "investigating": "INVESTIGATING"
    }
    
    if action not in valid_actions:
        raise HTTPException(status_code=400, detail="Invalid action")
        
    alert = await update_alert_status(db, alert_id, valid_actions[action])
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

from app.database.models import InvestigationNote
from pydantic import BaseModel
from sqlalchemy.future import select

class NoteCreate(BaseModel):
    note_text: str

@router.post("/{alert_id}/notes")
async def add_alert_note(alert_id: int, note: NoteCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    new_note = InvestigationNote(
        alert_id=alert_id,
        user_id=current_user.id,
        note_text=note.note_text
    )
    db.add(new_note)
    await db.commit()
    await db.refresh(new_note)
    return new_note

@router.get("/{alert_id}/notes")
async def get_alert_notes(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(InvestigationNote).where(InvestigationNote.alert_id == alert_id).order_by(InvestigationNote.created_at.desc()))
    return res.scalars().all()

