from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    @staticmethod
    def extract_features(events: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Extracts behavior features from a window of events.
        """
        features = {
            "failed_login_count": 0.0,
            "successful_login_count": 0.0,
            "unique_source_ip_count": 0.0,
            "unique_username_count": 0.0,
            "4xx_count": 0.0,
            "5xx_count": 0.0,
            "total_event_count": float(len(events)),
            "high_severity_count": 0.0
        }
        
        ips = set()
        usernames = set()
        
        for e in events:
            event_type = e.get("event_type", "")
            severity = e.get("severity", "")
            status_code = e.get("status_code")
            
            if event_type in ["AUTH_FAILURE", "SSH_FAILED_LOGIN"]:
                features["failed_login_count"] += 1
            if event_type in ["AUTH_SUCCESS", "SSH_LOGIN"]:
                features["successful_login_count"] += 1
                
            if severity in ["HIGH", "CRITICAL"]:
                features["high_severity_count"] += 1
                
            if status_code:
                if 400 <= status_code < 500:
                    features["4xx_count"] += 1
                elif status_code >= 500:
                    features["5xx_count"] += 1
                    
            ip = e.get("source_ip")
            if ip: ips.add(ip)
            
            user = e.get("username")
            if user: usernames.add(user)
            
        features["unique_source_ip_count"] = float(len(ips))
        features["unique_username_count"] = float(len(usernames))
        
        return features
