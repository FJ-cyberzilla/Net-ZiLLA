from .base import Detector
from typing import Any, Dict

class SMSScamDetector(Detector):
    def detect(self, data: Any) -> dict[str, Any]:
        # Analyze SMS content for scam patterns
        score = 0.0
        if isinstance(data, str) and "win a prize" in data.lower():
            score = 85.0
        return {"detected": score > 50.0, "score": score, "details": "Analysis complete"}
