import httpx
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.threat_intel.base import ThreatIntelProvider
from app.core.config import settings

logger = logging.getLogger(__name__)

class AbuseIPDBProvider(ThreatIntelProvider):
    def __init__(self):
        self.api_key = settings.THREAT_INTEL_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        return "abuseipdb"

    async def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None
            
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(self.base_url, headers=headers, params=params)
                
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                return {
                    "ip": ip,
                    "provider": self.name,
                    "is_malicious": score > 50,
                    "reputation_score": score,
                    "country": data.get('countryCode'),
                    "isp": data.get('isp'),
                    "domain": data.get('domain'),
                    "report_count": data.get('totalReports'),
                    "last_reported_at": data.get('lastReportedAt')
                }
            else:
                logger.error(f"AbuseIPDB error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to reach AbuseIPDB: {e}")
            return None
