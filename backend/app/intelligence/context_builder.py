from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession

from app.threat_intel.service import threat_intel_service
from app.ml.scoring import score_window

class ContextBuilder:
    async def build_context(self, db: AsyncSession, alert: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Gathers Threat Intel and ML Anomaly score for a given alert's context.
        """
        source_ip = alert.get("source_ip")
        
        reputation = None
        if source_ip:
            reputation = await threat_intel_service.get_ip_reputation(db, source_ip)
            
        ml_result = score_window(events)
        
        return {
            "reputation": reputation,
            "anomaly_result": ml_result,
            "events": events
        }

context_builder = ContextBuilder()
