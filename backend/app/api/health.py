from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.database.database import get_db

router = APIRouter()

@router.get("/")
async def health_check():
    return {"status": "ok", "service": "SecureLog AI API"}

@router.get("/database")
async def database_health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        # Avoid logging raw exception to the user, log internally (to be setup in logging)
        raise HTTPException(status_code=503, detail="Database connection failed")
