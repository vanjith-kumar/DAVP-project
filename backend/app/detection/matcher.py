import re
from typing import Dict, Any, List

def check_condition(event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    field = condition.get("field")
    operator = condition.get("operator")
    value = condition.get("value")
    
    event_val = event.get(field)
    if event_val is None:
        return False
        
    if operator == "equals":
        return event_val == value
    elif operator == "contains":
        return str(value) in str(event_val)
    elif operator == "regex":
        try:
            return bool(re.search(value, str(event_val)))
        except re.error:
            return False
    elif operator == "in":
        return event_val in value
    elif operator == "greater_than":
        try:
            return float(event_val) > float(value)
        except ValueError:
            return False
            
    return False

def match_event_to_rules(event: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluates a single event against a list of pattern-based rules.
    Returns a list of matched rules.
    """
    matched_rules = []
    
    for rule in rules:
        if not rule.get("enabled", False):
            continue
            
        config = rule.get("configuration", {})
        
        # Check event_types constraint if present
        event_types = config.get("event_types")
        if event_types and event.get("event_type") not in event_types:
            continue
            
        # Only process "pattern" rules immediately. 
        # Threshold/sequence rules require correlation history.
        if rule.get("rule_type") != "pattern":
            continue
            
        conditions = config.get("conditions", [])
        
        # All conditions must match (AND logic)
        all_match = True
        for cond in conditions:
            if not check_condition(event, cond):
                all_match = False
                break
                
        if all_match and conditions:
            matched_rules.append(rule)
            
    return matched_rules
