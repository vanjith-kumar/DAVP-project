from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List
from datetime import datetime, timezone
import logging
from app.ingestion.parsers import get_parser
from app.ingestion.normalizer import Normalizer
from app.ingestion.validator import Validator
from app.database.models import LogEvent
from app.detection.engine import detection_engine
from sqlalchemy import select

logger = logging.getLogger(__name__)

async def process_raw_log(db: AsyncSession, raw_line: str, source_id: int = None) -> LogEvent:
    # 1. Parse
    parser = get_parser(raw_line)
    parsed_data = parser.parse(raw_line)
    
    if not parsed_data:
        parsed_data = {
            "event_time": datetime.now(timezone.utc).isoformat(),
            "parse_status": "FAILED_PARSE",
            "raw_message": raw_line
        }

    # 2. Normalize
    normalized_data = Normalizer.normalize(parsed_data, raw_line)

    # 3. Validate
    validated_data = Validator.validate(normalized_data)
    
    if source_id:
        validated_data['source_id'] = source_id

    # Create DB Object (ignore extra fields not in model)
    model_keys = LogEvent.__table__.columns.keys()
    db_data = {k: v for k, v in validated_data.items() if k in model_keys}
    
    # Ensure event_time is a datetime object
    if isinstance(db_data.get('event_time'), str):
        try:
            db_data['event_time'] = datetime.fromisoformat(db_data['event_time'].replace('Z', '+00:00'))
        except Exception:
            db_data['event_time'] = datetime.now(timezone.utc)

    db_event = LogEvent(**db_data)
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)
    
    # 4. Detection
    # Convert back to dict for detection engine
    event_dict = {c.name: getattr(db_event, c.name) for c in db_event.__table__.columns}
    # For dates, convert to string
    if event_dict.get("event_time"):
        event_dict["event_time"] = event_dict["event_time"].isoformat()
        
    await detection_engine.process_event(db, event_dict)
    
    return db_event

async def get_logs(db: AsyncSession, skip: int = 0, limit: int = 50) -> List[LogEvent]:
    result = await db.execute(select(LogEvent).order_by(LogEvent.event_time.desc()).offset(skip).limit(limit))
    return result.scalars().all()
