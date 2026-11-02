import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

class CorrelationEngine:
    def __init__(self):
        # Very simple in-memory state for threshold tracking
        # Format: { rule_name: { group_key: [timestamps] } }
        self.state = {}
        # Format: { rule_name: { group_key: { "stage": int, "count": int, "last_time": dt } } }
        self.seq_state = {}
        
    def _get_group_key(self, event: Dict[str, Any], group_by: List[str]) -> str:
        if not group_by:
            return "global"
        return "-".join([str(event.get(k, "unknown")) for k in group_by])

    def evaluate_threshold(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        config = rule.get("configuration", {})
        rule_name = rule.get("name")
        
        event_types = config.get("event_types")
        if event_types and event.get("event_type") not in event_types:
            return False
            
        group_by = config.get("group_by", [])
        threshold = config.get("threshold", 1)
        time_window = config.get("time_window", 300)
        
        key = self._get_group_key(event, group_by)
        
        if rule_name not in self.state:
            self.state[rule_name] = {}
        if key not in self.state[rule_name]:
            self.state[rule_name][key] = []
            
        now = datetime.fromisoformat(event.get("event_time")) if event.get("event_time") else datetime.now(timezone.utc)
        
        self.state[rule_name][key].append(now)
        
        # Cleanup old events
        cutoff = now - timedelta(seconds=time_window)
        self.state[rule_name][key] = [t for t in self.state[rule_name][key] if t > cutoff]
        
        if len(self.state[rule_name][key]) >= threshold:
            # Clear state to avoid spamming the exact same alert immediately
            self.state[rule_name][key] = []
            return True
            
        return False

    def evaluate_sequence(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        config = rule.get("configuration", {})
        rule_name = rule.get("name")
        sequence = config.get("sequence", [])
        
        if not sequence:
            return False
            
        group_by = config.get("group_by", [])
        key = self._get_group_key(event, group_by)
        time_window = config.get("time_window", 600)
        
        if rule_name not in self.seq_state:
            self.seq_state[rule_name] = {}
            
        if key not in self.seq_state[rule_name]:
            self.seq_state[rule_name][key] = {"stage": 0, "count": 0, "last_time": None}
            
        state = self.seq_state[rule_name][key]
        now = datetime.fromisoformat(event.get("event_time")) if event.get("event_time") else datetime.now(timezone.utc)
        
        if state["last_time"] and (now - state["last_time"]).total_seconds() > time_window:
            # Reset if time window exceeded
            state["stage"] = 0
            state["count"] = 0
            
        current_stage_idx = state["stage"]
        if current_stage_idx >= len(sequence):
            return False
            
        current_stage = sequence[current_stage_idx]
        event_types = current_stage.get("event_types", [])
        
        if event.get("event_type") in event_types:
            state["count"] += 1
            state["last_time"] = now
            
            if state["count"] >= current_stage.get("min_count", 1):
                # Advance stage
                state["stage"] += 1
                state["count"] = 0
                
                if state["stage"] >= len(sequence):
                    # Sequence completed
                    self.seq_state[rule_name][key] = {"stage": 0, "count": 0, "last_time": None}
                    return True
        else:
            # If event doesn't match current stage, and doesn't match stage 0, we might want to reset
            # Basic implementation: only reset if it breaks a strict sequence. 
            pass

        return False

correlation_engine = CorrelationEngine()
