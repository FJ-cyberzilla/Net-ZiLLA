"""Base detector module."""
from abc import ABC, abstractmethod
from typing import Any


class Detector(ABC):
    """Base class for all detectors."""

    @abstractmethod
    def detect(self, data: Any) -> dict[str, Any]:
        """
        Analyzes the provided data and returns a dictionary
        containing the detection results (e.g., score, confidence, findings).
        """
