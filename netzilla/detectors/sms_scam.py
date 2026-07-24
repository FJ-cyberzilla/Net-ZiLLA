"""
Module for detecting SMS scam messages.
"""
import re

from netzilla.interfaces import SMSDetector


class SMSScamDetector(SMSDetector):
    def analyze(self, message: str) -> float:
        """Return scam probability score (0-100)."""
        score = 0.0
        lower = message.lower()

        # Urgency and pressure
        if any(
            w in lower for w in ["urgent", "immediate", "action required", "suspended"]
        ):
            score += 30

        # Prize/Winning
        if any(
            w in lower
            for w in ["won", "prize", "gift card", "reward", "congratulations"]
        ):
            score += 40

        # Banking/Verification
        if any(w in lower for w in ["bank", "verify", "account", "login", "secure"]):
            score += 30

        # Links
        urls = self.extract_urls(message)
        if urls:
            score += 20
            if any("bit.ly" in url or "t.co" in url for url in urls):
                score += 20

        return min(score, 100.0)

    def extract_urls(self, message: str) -> list[str]:
        """Extract URLs from SMS text."""
        return re.findall(r"https?://\S+", message)

    def classify_tactic(self, message: str) -> str:
        """Classify the scam tactic used."""
        lower = message.lower()
        if "won" in lower or "prize" in lower or "reward" in lower:
            return "prize_scam"
        if "bank" in lower or "verify" in lower or "secure" in lower:
            return "credential_harvest"
        if "urgent" in lower or "suspended" in lower:
            return "scare_tactic"
        return "generic_scam"
