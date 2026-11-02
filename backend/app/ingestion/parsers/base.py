from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class LogParser(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        pass

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        pass
