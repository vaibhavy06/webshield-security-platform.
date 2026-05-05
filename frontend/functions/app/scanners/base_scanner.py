from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform the scan on the target URL/Domain.
        Must return a dictionary with standardized output.
        """
        pass

    def handle_error(self, error: Exception) -> Dict[str, Any]:
        return {
            "status": "error",
            "message": str(error)
        }
