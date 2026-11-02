from app.detection.matcher import match_event_to_rules
from app.detection.rules import DEFAULT_RULES

def test_sql_injection_rule():
    event = {
        "event_type": "HTTP_REQUEST",
        "raw_message": "GET /api?id=1 union select password from users HTTP/1.1",
        "source_ip": "10.0.0.1"
    }
    matches = match_event_to_rules(event, DEFAULT_RULES)
    assert len(matches) > 0
    assert matches[0]["name"] == "Potential SQL Injection Pattern"

def test_sensitive_path_rule():
    event = {
        "event_type": "HTTP_REQUEST",
        "path": "/admin/config",
        "source_ip": "10.0.0.1"
    }
    matches = match_event_to_rules(event, DEFAULT_RULES)
    assert len(matches) > 0
    assert matches[0]["name"] == "Sensitive Path Access"
