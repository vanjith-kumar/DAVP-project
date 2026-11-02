import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from app.ingestion.parsers.base import LogParser

# Oct 11 10:45:01 hostname sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
AUTH_REGEX = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>[a-zA-Z0-9_\-]+)(?:\[\d+\])?:\s+(?P<message>.*)$'
)

class LinuxAuthParser(LogParser):
    @property
    def name(self) -> str:
        return "linux_auth"

    def can_parse(self, raw_line: str) -> bool:
        return bool(AUTH_REGEX.match(raw_line))

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        match = AUTH_REGEX.match(raw_line)
        if not match:
            return None
        
        data = match.groupdict()
        msg = data.get("message", "")
        service = data.get("service", "")
        
        # Parse timestamp (syslog lacks year, assume current year)
        year = datetime.now().year
        time_str = f"{year} {data.get('month')} {data.get('day')} {data.get('time')}"
        try:
            event_time = datetime.strptime(time_str, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            event_time = datetime.now(timezone.utc).isoformat()

        event_type = "UNKNOWN"
        severity = "INFO"
        username = None
        source_ip = None
        
        if "sshd" in service:
            if "Failed password" in msg:
                event_type = "SSH_FAILED_LOGIN"
                severity = "WARNING"
                ip_match = re.search(r'from (\S+)', msg)
                if ip_match: source_ip = ip_match.group(1)
                user_match = re.search(r'for (?:invalid user )?(\S+)', msg)
                if user_match: username = user_match.group(1)
            elif "Accepted password" in msg or "Accepted publickey" in msg:
                event_type = "SSH_LOGIN"
                ip_match = re.search(r'from (\S+)', msg)
                if ip_match: source_ip = ip_match.group(1)
                user_match = re.search(r'for (\S+)', msg)
                if user_match: username = user_match.group(1)
            elif "Invalid user" in msg:
                event_type = "INVALID_USER"
                severity = "WARNING"
                ip_match = re.search(r'from (\S+)', msg)
                if ip_match: source_ip = ip_match.group(1)
                user_match = re.search(r'user (\S+)', msg)
                if user_match: username = user_match.group(1)
        elif "sudo" in service:
            event_type = "SUDO_ACTIVITY"
            user_match = re.search(r'^\s*(\S+) :', msg)
            if user_match: username = user_match.group(1)
            if "COMMAND=" in msg:
                severity = "INFO"

        return {
            "event_time": event_time,
            "host": data.get("host"),
            "service": service,
            "message": msg,
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "username": username,
            "parser_name": self.name
        }
