from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.ingestion.parsers.base import LogParser

class GenericParser(LogParser):
    @property
    def name(self) -> str:
        return "generic"

    def can_parse(self, raw_line: str) -> bool:
        return True  # Fallback parser

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        # A very basic fallback that just puts the whole string into the message
        return {
            "event_time": datetime.now(timezone.utc).isoformat(),
            "message": raw_line.strip(),
            "event_type": "UNKNOWN",
            "severity": "INFO",
            "parser_name": self.name
        }
