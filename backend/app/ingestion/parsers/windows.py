import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.ingestion.parsers.base import LogParser

class WindowsJsonParser(LogParser):
    @property
    def name(self) -> str:
        return "windows_json"

    def can_parse(self, raw_line: str) -> bool:
        try:
            data = json.loads(raw_line)
            return "EventID" in data or "Provider" in data
        except Exception:
            return False

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(raw_line)
        except Exception:
            return None
            
        event_time_str = data.get("TimeCreated")
        try:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00")).isoformat()
        except Exception:
            event_time = datetime.now(timezone.utc).isoformat()

        event_id = str(data.get("EventID", ""))
        event_type = "UNKNOWN"
        severity = "INFO"
        message = data.get("Message", f"Windows Event {event_id}")
        
        # 4624 Successful Logon, 4625 Failed Logon
        if event_id == "4624":
            event_type = "AUTH_SUCCESS"
        elif event_id == "4625":
            event_type = "AUTH_FAILURE"
            severity = "WARNING"
            
        event_data = data.get("EventData", {})
        username = event_data.get("TargetUserName")
        source_ip = event_data.get("IpAddress")

        return {
            "event_time": event_time,
            "host": data.get("Computer"),
            "event_type": event_type,
            "severity": severity,
            "username": username,
            "source_ip": source_ip,
            "message": message,
            "parser_name": self.name
        }
