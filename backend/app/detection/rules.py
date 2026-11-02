# Bootstrap initial rules
DEFAULT_RULES = [
    {
        "name": "Repeated Authentication Failures",
        "description": "Detects multiple failed login attempts from the same source IP.",
        "rule_type": "threshold",
        "severity": "MEDIUM",
        "enabled": True,
        "configuration": {
            "event_types": ["AUTH_FAILURE", "INVALID_USER"],
            "group_by": ["source_ip"],
            "threshold": 5,
            "time_window": 300,
            "message_template": "Repeated authentication failures detected from {source_ip}"
        }
    },
    {
        "name": "SSH Brute-Force Pattern",
        "description": "Detects repeated SSH authentication failures.",
        "rule_type": "threshold",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "event_types": ["SSH_FAILED_LOGIN"],
            "group_by": ["source_ip"],
            "threshold": 5,
            "time_window": 300,
            "message_template": "Repeated SSH authentication failures detected from {source_ip}"
        }
    },
    {
        "name": "Successful Login After Repeated Failures",
        "description": "Detects a successful authentication following multiple failures.",
        "rule_type": "sequence",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "sequence": [
                {"event_types": ["AUTH_FAILURE", "SSH_FAILED_LOGIN"], "min_count": 3},
                {"event_types": ["AUTH_SUCCESS", "SSH_LOGIN"], "min_count": 1}
            ],
            "group_by": ["source_ip"],
            "time_window": 600,
            "message_template": "Suspicious authentication sequence detected for {source_ip}"
        }
    },
    {
        "name": "Suspicious HTTP Status Pattern",
        "description": "Detects excessive 401, 403, or 404 responses from the same source.",
        "rule_type": "threshold",
        "severity": "MEDIUM",
        "enabled": True,
        "configuration": {
            "event_types": ["HTTP_ERROR"],
            "conditions": [
                {"field": "status_code", "operator": "in", "value": [401, 403, 404]}
            ],
            "group_by": ["source_ip"],
            "threshold": 20,
            "time_window": 60,
            "message_template": "Abnormal HTTP error response pattern detected from {source_ip}"
        }
    },
    {
        "name": "Sensitive Path Access",
        "description": "Detects requests targeting sensitive paths.",
        "rule_type": "pattern",
        "severity": "MEDIUM",
        "enabled": True,
        "configuration": {
            "event_types": ["HTTP_REQUEST", "HTTP_ERROR"],
            "conditions": [
                {"field": "path", "operator": "regex", "value": r"^/(admin|login|\.env|config|wp-admin|server-status)"}
            ],
            "message_template": "Sensitive URL access detected on path {path} from {source_ip}"
        }
    },
    {
        "name": "Potential SQL Injection Pattern",
        "description": "Detects common SQL injection indicators in requests.",
        "rule_type": "pattern",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "conditions": [
                {"field": "raw_message", "operator": "regex", "value": r"(?i)(union select|or 1=1|information_schema|sleep\(|benchmark\()"}
            ],
            "message_template": "Potential SQL injection pattern observed in HTTP request from {source_ip}"
        }
    },
    {
        "name": "Suspicious Command Injection Pattern",
        "description": "Detects shell metacharacters often used in command injection.",
        "rule_type": "pattern",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "conditions": [
                {"field": "raw_message", "operator": "regex", "value": r"(; whoami|&& whoami|\| whoami|\$\(.*\))"}
            ],
            "message_template": "Command injection indicator observed from {source_ip}"
        }
    },
    {
        "name": "Suspicious PowerShell Activity",
        "description": "Detects suspicious powershell command usage.",
        "rule_type": "pattern",
        "severity": "MEDIUM",
        "enabled": True,
        "configuration": {
            "conditions": [
                {"field": "raw_message", "operator": "regex", "value": r"(?i)(powershell|cmd\.exe|EncodedCommand|IEX|Invoke-WebRequest)"}
            ],
            "message_template": "Suspicious command activity indicator observed."
        }
    },
    {
        "name": "Privilege Escalation Indicator",
        "description": "Detects suspicious combinations involving privilege elevation.",
        "rule_type": "pattern",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "conditions": [
                {"field": "raw_message", "operator": "regex", "value": r"(?i)(sudo|su|administrator|root|privilege)"}
            ],
            "message_template": "Suspicious privilege activity observed."
        }
    },
    {
        "name": "Security Control Failure",
        "description": "Detects messages indicating security controls being disabled.",
        "rule_type": "pattern",
        "severity": "HIGH",
        "enabled": True,
        "configuration": {
            "conditions": [
                {"field": "raw_message", "operator": "regex", "value": r"(?i)(firewall disabled|audit disabled|security service stopped)"}
            ],
            "message_template": "Security control disabled/stopped indicator observed."
        }
    }
]
