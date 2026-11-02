import re
from typing import Dict, Any, List

def sanitize_logs(events: List[Dict[str, Any]]) -> str:
    """
    Sanitize sensitive information from logs before sending to LLM.
    """
    sanitized_lines = []
    
    # Basic redaction patterns
    patterns = [
        (re.compile(r'(?i)password\s*=\s*\S+'), 'password=[REDACTED]'),
        (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+'), 'Bearer [REDACTED]'),
        (re.compile(r'(?i)api_key\s*=\s*\S+'), 'api_key=[REDACTED]'),
        (re.compile(r'(?i)session_cookie\s*=\s*\S+'), 'session_cookie=[REDACTED]')
    ]
    
    for event in events:
        msg = event.get('raw_message', '')
        if not msg: continue
        
        for p, repl in patterns:
            msg = p.sub(repl, msg)
            
        sanitized_lines.append(f"[{event.get('event_time')}] {msg}")
        
    return "\n".join(sanitized_lines)
