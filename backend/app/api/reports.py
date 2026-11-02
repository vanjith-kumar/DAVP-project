from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.database.models import Incident, IncidentEvidence, InvestigationNote, AuditLog, LogEvent

from app.reports.generator import generate_incident_pdf, generate_events_csv

router = APIRouter()

@router.get("/incident/{incident_id}/pdf")
async def get_incident_pdf(incident_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    ev_res = await db.execute(select(IncidentEvidence).where(IncidentEvidence.incident_id == incident_id))
    evidence = ev_res.scalars().all()
    
    note_res = await db.execute(select(InvestigationNote).where(InvestigationNote.incident_id == incident_id))
    notes = note_res.scalars().all()
    
    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action="REPORT_GENERATED",
        target_type="incident",
        target_id=str(incident_id)
    )
    db.add(audit)
    await db.commit()
    
    # Convert ORM objects to dicts for the generator
    inc_dict = {
        "incident_number": incident.incident_number,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "priority": incident.priority,
        "status": incident.status,
        "created_at": incident.created_at
    }
    ev_dicts = [{"evidence_type": e.evidence_type, "source_reference": e.source_reference, "description": e.description, "collected_at": e.collected_at} for e in evidence]
    note_dicts = [{"note_text": n.note_text, "created_at": n.created_at, "user_id": n.user_id} for n in notes]
    
    pdf_buffer = generate_incident_pdf(inc_dict, ev_dicts, note_dicts)
    
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=incident_{incident.incident_number}.pdf"}
    )

@router.get("/events/csv")
async def get_events_csv(limit: int = 1000, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(LogEvent).order_by(LogEvent.event_time.desc()).limit(limit))
    events = res.scalars().all()
    
    audit = AuditLog(
        actor_id=current_user.id,
        action="CSV_EXPORTED",
        target_type="events",
        target_id="bulk"
    )
    db.add(audit)
    await db.commit()
    
    csv_content = generate_events_csv(events)
    return PlainTextResponse(
        csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events_export.csv"}
    )
