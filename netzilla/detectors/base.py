from abc import ABC, abstractmethod
from typing import Any, Dict

class Detector(ABC):
    @abstractmethod
    def detect(self, data: Any) -> dict[str, Any]:
        """
        Analyzes the provided data and returns a dictionary
        containing the detection results (e.g., score, confidence, findings).
        """
        pass
