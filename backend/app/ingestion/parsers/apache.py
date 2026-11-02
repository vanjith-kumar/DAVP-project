import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.ingestion.parsers.base import LogParser

# Common Apache format: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
APACHE_REGEX = re.compile(
    r'^(?P<source_ip>[\d\.]+|[\w\:]+) \S+ (?P<username>\S+) '
    r'\[(?P<event_time>.*?)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status_code>\d{3}) (?P<response_size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

class ApacheParser(LogParser):
    @property
    def name(self) -> str:
        return "apache"

    def can_parse(self, raw_line: str) -> bool:
        return bool(APACHE_REGEX.match(raw_line))

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        match = APACHE_REGEX.match(raw_line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        event_time_str = data.get("event_time")
        try:
            # 10/Oct/2000:13:55:36 -0700
            event_time = datetime.strptime(event_time_str, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except Exception:
            event_time = datetime.now(timezone.utc).isoformat()
            
        status_code = int(data.get("status_code", 200))
        severity = "INFO"
        if status_code >= 500:
            severity = "ERROR"
        elif status_code >= 400:
            severity = "WARNING"
            
        return {
            "event_time": event_time,
            "source_ip": data.get("source_ip"),
            "username": data.get("username") if data.get("username") != "-" else None,
            "method": data.get("method"),
            "path": data.get("path"),
            "protocol": data.get("protocol"),
            "status_code": status_code,
            "user_agent": data.get("user_agent"),
            "event_type": "HTTP_REQUEST" if status_code < 400 else "HTTP_ERROR",
            "severity": severity,
            "message": f"Apache HTTP {status_code} on {data.get('path')}",
            "parser_name": self.name
        }
