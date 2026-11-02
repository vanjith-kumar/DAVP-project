from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any, List
import uuid
from datetime import datetime, timezone

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.database.models import Incident, Alert, IncidentEvidence, InvestigationNote, AuditLog

router = APIRouter()

@router.post("/from-alert/{alert_id}")
async def create_incident_from_alert(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Fetch Alert
    alert_res = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = alert_res.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    # 2. Create Incident
    now = datetime.now(timezone.utc)
    incident_number = f"INC-{now.year}-{str(uuid.uuid4())[:8].upper()}"
    
    incident = Incident(
        incident_number=incident_number,
        title=alert.title,
        description=f"Generated from Alert #{alert.id}: {alert.description}",
        severity=alert.severity,
        priority="HIGH" if alert.severity == "CRITICAL" else "MEDIUM",
        status="OPEN",
        risk_score=alert.risk_score,
        source="ALERT_ESCALATION",
        created_by=current_user.id,
        created_at=now
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    
    # 3. Add Evidence
    evidence = IncidentEvidence(
        incident_id=incident.id,
        evidence_type="ALERT",
        source_reference=str(alert.id),
        description=f"Initial escalating alert: {alert.title}",
        collected_at=now,
        collected_by=current_user.id
    )
    db.add(evidence)
    
    # 4. Migrate/link Investigation Notes
    notes_res = await db.execute(select(InvestigationNote).where(InvestigationNote.alert_id == alert.id))
    notes = notes_res.scalars().all()
    for note in notes:
        note.incident_id = incident.id
        
    # 5. Log Audit
    audit = AuditLog(
        actor_id=current_user.id,
        action="INCIDENT_CREATED",
        target_type="incident",
        target_id=str(incident.id),
        timestamp=now
    )
    db.add(audit)
    
    # 6. Update Alert Status
    alert.status = "INVESTIGATING"
    
    await db.commit()
    return {"status": "success", "incident_id": incident.id, "incident_number": incident.number if hasattr(incident, 'number') else incident_number}

@router.get("/")
async def get_incidents(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Incident).order_by(Incident.created_at.desc()))
    return res.scalars().all()

@router.get("/{incident_id}")
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    # Fetch evidence and notes
    ev_res = await db.execute(select(IncidentEvidence).where(IncidentEvidence.incident_id == incident_id))
    evidence = ev_res.scalars().all()
    
    note_res = await db.execute(select(InvestigationNote).where(InvestigationNote.incident_id == incident_id))
    notes = note_res.scalars().all()
    
    return {
        "incident": incident,
        "evidence": evidence,
        "notes": notes
    }
