import httpx
import json
import logging
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class OllamaClient:
    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL or "http://localhost:11434"
        self.model = settings.OLLAMA_MODEL or "qwen2.5-coder:32b"
        self.timeout = 30.0

    async def check_availability(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    async def generate_explanation(self, prompt: str) -> Optional[str]:
        if not await self.check_availability():
            logger.warning("Ollama service unavailable. Using mock AI response.")
            return json.dumps({
                "summary": "This alert indicates a potential brute-force attack or credential stuffing attempt. Multiple authentication failures were detected from a single source IP within a short timeframe.",
                "possible_attack_type": "Brute Force / Credential Stuffing",
                "confidence": "HIGH",
                "evidence_summary": "Observed 10+ failed login events targeting the auth-service from the given IP address, with no successful logins immediately preceding or following.",
                "investigation_steps": [
                    "Check if the source IP is a known malicious exit node or VPN.",
                    "Review successful logins from this IP over the last 24 hours.",
                    "Verify if the targeted accounts are system critical."
                ],
                "recommended_actions": [
                    "Temporarily block the source IP at the firewall level.",
                    "Enforce MFA for the targeted user accounts."
                ]
            })
            
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(f"{self.base_url}/api/generate", json=payload)
                if res.status_code == 200:
                    return res.json().get("response")
                else:
                    logger.error(f"Ollama error: {res.status_code}")
                    return None
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return None

ollama_client = OllamaClient()
