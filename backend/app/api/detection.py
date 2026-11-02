from fastapi import APIRouter, Depends, HTTPException
from typing import List

from app.core.permissions import get_current_user, get_current_active_admin
from app.schemas.users import User
from app.schemas.rules import DetectionRuleResponse
from app.detection.engine import detection_engine

router = APIRouter()

@router.get("/rules", response_model=List[DetectionRuleResponse])
async def get_rules(current_user: User = Depends(get_current_user)):
    # In Phase 2, rules are in memory (DEFAULT_RULES). We return them formatted as expected.
    # We assign mock IDs for the API response since they aren't DB models yet.
    response = []
    for idx, rule in enumerate(detection_engine.rules):
        response.append({
            "id": idx + 1,
            "name": rule["name"],
            "description": rule.get("description"),
            "rule_type": rule["rule_type"],
            "severity": rule["severity"],
            "enabled": rule["enabled"],
            "configuration": rule["configuration"]
        })
    return response

@router.patch("/rules/{rule_id}/enable")
async def enable_rule(rule_id: int, current_user: User = Depends(get_current_active_admin)):
    if 1 <= rule_id <= len(detection_engine.rules):
        detection_engine.rules[rule_id - 1]["enabled"] = True
        return {"message": f"Rule {rule_id} enabled"}
    raise HTTPException(status_code=404, detail="Rule not found")

@router.patch("/rules/{rule_id}/disable")
async def disable_rule(rule_id: int, current_user: User = Depends(get_current_active_admin)):
    if 1 <= rule_id <= len(detection_engine.rules):
        detection_engine.rules[rule_id - 1]["enabled"] = False
        return {"message": f"Rule {rule_id} disabled"}
    raise HTTPException(status_code=404, detail="Rule not found")
