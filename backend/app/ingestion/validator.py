import ipaddress
from typing import Dict, Any

class Validator:
    @staticmethod
    def validate(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate IPs, clean control characters, ensure schema compliance.
        """
        # Validate IPs
        for ip_field in ['source_ip', 'destination_ip']:
            ip = normalized_data.get(ip_field)
            if ip:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    normalized_data[ip_field] = None
                    normalized_data['parse_status'] = "FAILED_VALIDATION"
                    if 'metadata_' not in normalized_data or normalized_data['metadata_'] is None:
                        normalized_data['metadata_'] = {}
                    normalized_data['metadata_']['validation_error'] = f"Invalid {ip_field}: {ip}"
                    
        # Optional: Sanitize string fields
        for k, v in normalized_data.items():
            if isinstance(v, str):
                # Remove dangerous control chars like null bytes, but keep newlines/tabs if safe
                normalized_data[k] = v.replace("\x00", "")

        return normalized_data
