from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class ThreatIntelProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        pass
