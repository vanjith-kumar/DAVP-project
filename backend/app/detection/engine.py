from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from app.detection.matcher import match_event_to_rules
from app.detection.correlation import correlation_engine
from app.detection.alert_generator import alert_generator
from app.detection.rules import DEFAULT_RULES

class DetectionEngine:
    def __init__(self):
        # In a real app, rules would be loaded from DB periodically
        self.rules = DEFAULT_RULES

    async def process_event(self, db: AsyncSession, event: Dict[str, Any]):
        # 1. Evaluate pattern rules
        matched_pattern_rules = match_event_to_rules(event, self.rules)
        for rule in matched_pattern_rules:
            await alert_generator.generate_alert(db, rule, event)

        # 2. Evaluate threshold rules
        for rule in self.rules:
            if rule.get("rule_type") == "threshold":
                if correlation_engine.evaluate_threshold(event, rule):
                    await alert_generator.generate_alert(db, rule, event)
                    
        # 3. Evaluate sequence rules
        for rule in self.rules:
            if rule.get("rule_type") == "sequence":
                if correlation_engine.evaluate_sequence(event, rule):
                    await alert_generator.generate_alert(db, rule, event)

detection_engine = DetectionEngine()
