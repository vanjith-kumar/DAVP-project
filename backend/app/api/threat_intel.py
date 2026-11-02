from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.threat_intel.service import threat_intel_service

router = APIRouter()

@router.get("/ip/{ip}")
async def check_ip(ip: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Validate IP basic format to prevent injection
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
        
    result = await threat_intel_service.get_ip_reputation(db, ip)
    return result

@router.get("/status")
async def get_ti_status(current_user: User = Depends(get_current_user)):
    from app.core.config import settings
    return {
        "provider": "abuseipdb" if settings.THREAT_INTEL_API_KEY else "mock",
        "enabled": True
    }
