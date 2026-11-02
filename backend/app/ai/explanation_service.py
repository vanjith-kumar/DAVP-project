import json
import logging
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone

from app.ai.prompts import SECURITY_EXPLANATION_PROMPT_V1
from app.ai.safety import sanitize_logs
from app.ai.ollama_client import ollama_client
from app.schemas.ai import AIExplanationResponse
from app.database.models import AIExplanation, Alert

logger = logging.getLogger(__name__)

class ExplanationService:
    async def explain_alert(self, db: AsyncSession, alert_id: int, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates and saves an AI explanation for an alert.
        """
        # Fetch alert to ensure it exists
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalars().first()
        if not alert:
            return {"status": "ERROR", "message": "Alert not found"}
            
        # Format Prompt
        events = context.get('events', [])
        sanitized_events = sanitize_logs(events)
        
        prompt = SECURITY_EXPLANATION_PROMPT_V1.format(
            title=alert.title,
            rule_name=alert.detection_type,
            anomaly_score=context.get('anomaly_score', 'N/A'),
            reputation=context.get('reputation', 'N/A'),
            source_ip=alert.source_ip or 'unknown',
            events=sanitized_events
        )
        
        raw_response = await ollama_client.generate_explanation(prompt)
        
        if not raw_response:
            # Save failed explanation
            return await self._save_explanation(db, alert_id, "UNAVAILABLE", None)
            
        # Validate output
        try:
            parsed = json.loads(raw_response)
            validated = AIExplanationResponse(**parsed)
            return await self._save_explanation(db, alert_id, "SUCCESS", validated.model_dump())
        except Exception as e:
            logger.error(f"Failed to validate AI output: {e}")
            return await self._save_explanation(db, alert_id, "VALIDATION_FAILED", None)

    async def _save_explanation(self, db: AsyncSession, alert_id: int, status: str, explanation: dict) -> dict:
        # Check if exists
        res = await db.execute(select(AIExplanation).where(AIExplanation.alert_id == alert_id))
        existing = res.scalars().first()
        
        if existing:
            existing.generation_status = status
            if explanation:
                existing.explanation = explanation
                existing.summary = explanation.get("summary", "")
                existing.confidence = explanation.get("confidence", "UNKNOWN")
            existing.generated_at = datetime.now(timezone.utc)
            db_exp = existing
        else:
            db_exp = AIExplanation(
                alert_id=alert_id,
                model_name=ollama_client.model,
                prompt_version="SECURITY_EXPLANATION_PROMPT_V1",
                summary=explanation.get("summary", "") if explanation else "",
                explanation=explanation or {},
                confidence=explanation.get("confidence", "UNKNOWN") if explanation else "UNKNOWN",
                generation_status=status
            )
            db.add(db_exp)
            
        await db.commit()
        
        return {
            "status": status,
            "explanation": explanation
        }

explanation_service = ExplanationService()
