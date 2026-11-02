from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from app.database.models import Alert

async def get_alerts(db: AsyncSession, skip: int = 0, limit: int = 50, status: Optional[str] = None) -> List[Alert]:
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    query = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    return result.scalars().all()

async def get_alert(db: AsyncSession, alert_id: int) -> Optional[Alert]:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalars().first()

async def update_alert_status(db: AsyncSession, alert_id: int, status: str) -> Optional[Alert]:
    alert = await get_alert(db, alert_id)
    if alert:
        alert.status = status
        await db.commit()
        await db.refresh(alert)
    return alert
