import ipaddress
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update

from app.threat_intel.providers.mock import MockProvider
from app.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from app.database.models import ThreatIntelCache
from app.core.config import settings

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        self.mock_provider = MockProvider()
        self.abuse_provider = AbuseIPDBProvider()
        self.cache_ttl = 3600 # 1 hour

    def _is_public(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not addr.is_private and not addr.is_loopback
        except ValueError:
            return False

    async def get_ip_reputation(self, db: AsyncSession, ip: str) -> Dict[str, Any]:
        if not self._is_public(ip):
            return {
                "ip": ip,
                "provider": "local",
                "status": "SKIPPED",
                "message": "Private/loopback IP address not checked"
            }

        # Check Cache
        result = await db.execute(select(ThreatIntelCache).where(ThreatIntelCache.ip_address == ip))
        cached = result.scalars().first()
        
        now = datetime.now(timezone.utc)
        if cached:
            expiration = cached.expiration.replace(tzinfo=timezone.utc) if cached.expiration.tzinfo is None else cached.expiration
            if expiration > now:
                return cached.result

        # Lookup
        provider = self.abuse_provider if settings.THREAT_INTEL_API_KEY else self.mock_provider
        
        lookup_result = await provider.lookup_ip(ip)
        
        if not lookup_result:
            return {
                "ip": ip,
                "provider": provider.name,
                "status": "UNAVAILABLE",
                "message": "Provider lookup failed"
            }
            
        lookup_result["status"] = "SUCCESS"
        
        # Save to Cache
        expiration = now + timedelta(seconds=self.cache_ttl)
        if cached:
            cached.result = lookup_result
            cached.lookup_timestamp = now
            cached.expiration = expiration
        else:
            new_cache = ThreatIntelCache(
                ip_address=ip,
                provider=provider.name,
                result=lookup_result,
                lookup_timestamp=now,
                expiration=expiration
            )
            db.add(new_cache)
            
        await db.commit()
        return lookup_result

threat_intel_service = ThreatIntelService()
