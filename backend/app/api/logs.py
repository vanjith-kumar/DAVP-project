from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.schemas.logs import LogEventResponse, LogIngest, LogBatchIngest
from app.services.log_service import process_raw_log, get_logs

router = APIRouter()

@router.get("/", response_model=List[LogEventResponse])
async def read_logs(skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return await get_logs(db, skip=skip, limit=limit)

@router.post("/ingest", response_model=LogEventResponse)
async def ingest_log(log_data: LogIngest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Basic API ingestion endpoint
    event = await process_raw_log(db, log_data.message, log_data.source_id)
    return event

@router.post("/ingest/batch")
async def ingest_logs_batch(batch_data: LogBatchIngest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    if len(batch_data.messages) > 500:
        raise HTTPException(status_code=400, detail="Batch size exceeds maximum of 500")
    
    events = []
    for msg in batch_data.messages:
        event = await process_raw_log(db, msg, batch_data.source_id)
        events.append(event)
    return {"message": f"Successfully ingested {len(events)} events"}

