from app.ingestion.parsers import get_parser

def test_apache_parser():
    raw = '192.168.1.50 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024'
    parser = get_parser(raw)
    assert parser.name == "apache"
    parsed = parser.parse(raw)
    assert parsed["source_ip"] == "192.168.1.50"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/index.html"
    assert parsed["status_code"] == 200

def test_linux_auth_parser():
    raw = 'Oct 11 10:45:01 hostname sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2'
    parser = get_parser(raw)
    assert parser.name == "linux_auth"
    parsed = parser.parse(raw)
    assert parsed["source_ip"] == "192.168.1.100"
    assert parsed["username"] == "admin"
    assert parsed["event_type"] == "SSH_FAILED_LOGIN"
    
def test_windows_parser():
    raw = '{"EventID": 4624, "TimeCreated": "2026-10-11T10:45:01Z", "EventData": {"TargetUserName": "admin", "IpAddress": "1.2.3.4"}}'
    parser = get_parser(raw)
    assert parser.name == "windows_json"
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "AUTH_SUCCESS"
    assert parsed["source_ip"] == "1.2.3.4"
