from typing import Dict, Any

class RiskEngine:
    @staticmethod
    def calculate_risk(alert: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0
        factors = []
        
        # Base risk from rule severity
        severity = alert.get("severity", "LOW")
        if severity == "CRITICAL":
            risk_score += 60
            factors.append("Critical rule matched")
        elif severity == "HIGH":
            risk_score += 40
            factors.append("High severity rule matched")
        elif severity == "MEDIUM":
            risk_score += 20
            factors.append("Medium severity rule matched")
            
        # ML Anomaly
        ml_score = context.get("anomaly_result", {}).get("anomaly_score", 0)
        if ml_score > 0.8:
            risk_score += 30
            factors.append(f"Highly anomalous behavior (Score: {ml_score})")
        elif ml_score > 0.6:
            risk_score += 15
            factors.append(f"Suspicious behavior (Score: {ml_score})")
            
        # Threat Intel
        reputation = context.get("reputation", {})
        if reputation and reputation.get("is_malicious"):
            ti_score = reputation.get("reputation_score", 0)
            risk_score += (ti_score * 0.3)
            factors.append(f"Source IP known malicious (Reputation: {ti_score})")
            
        # Cap
        risk_score = min(100, int(risk_score))
        
        level = "LOW"
        if risk_score >= 80: level = "CRITICAL"
        elif risk_score >= 60: level = "HIGH"
        elif risk_score >= 30: level = "MEDIUM"
        
        return {
            "risk_score": risk_score,
            "risk_level": level,
            "risk_factors": factors
        }
