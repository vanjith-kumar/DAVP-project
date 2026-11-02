import json
from typing import Dict, Any

class Normalizer:
    @staticmethod
    def normalize(parsed_data: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
        """
        Normalize fields (e.g., lowercase HTTP methods, standardize severity, etc.)
        """
        # Ensure we always keep the raw message
        parsed_data['raw_message'] = raw_line

        # Normalize HTTP Method
        if parsed_data.get('method'):
            parsed_data['method'] = str(parsed_data['method']).upper()

        # Normalize Severity
        if parsed_data.get('severity'):
            sev = str(parsed_data['severity']).upper()
            if sev not in ["INFO", "WARNING", "ERROR", "CRITICAL"]:
                sev = "INFO"
            parsed_data['severity'] = sev

        # Limit large fields (e.g., path, message, user_agent)
        for field in ['path', 'message', 'user_agent']:
            if parsed_data.get(field) and len(str(parsed_data[field])) > 10000:
                parsed_data[field] = str(parsed_data[field])[:10000] + "... [TRUNCATED]"
        
        parsed_data['parse_status'] = "SUCCESS"
        return parsed_data
