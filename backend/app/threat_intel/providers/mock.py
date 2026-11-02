from app.threat_intel.base import ThreatIntelProvider
from typing import Dict, Any, Optional
import asyncio
from datetime import datetime, timezone

class MockProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "mock"

    async def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        # Simulate network delay
        await asyncio.sleep(0.1)
        
        is_malicious = False
        reputation_score = 0
        
        if ip == "10.0.0.99" or ip.startswith("100."):
            is_malicious = True
            reputation_score = 100
        elif ip == "192.168.1.100":
            # Just some mock suspicious activity
            is_malicious = True
            reputation_score = 85
            
        return {
            "ip": ip,
            "provider": self.name,
            "is_malicious": is_malicious,
            "reputation_score": reputation_score,
            "country": "MockCountry",
            "isp": "MockISP",
            "report_count": 10 if is_malicious else 0,
            "last_reported_at": datetime.now(timezone.utc).isoformat() if is_malicious else None
        }
