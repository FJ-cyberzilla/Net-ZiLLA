from netzilla.interfaces import RedirectHop

class PhishingDetectorImplementation:
    """Detects phishing attempts in URLs and content."""
    
    def analyze(self, url: str, content: str | None = None, redirects: list[RedirectHop] | None = None) -> float:
        """Return phishing probability score (0-100)."""
        score = 0.0
        if redirects and len(redirects) > 3:
            score += 20.0
        return min(score, 100.0)
    
    def get_indicators(self, url: str) -> list[str]:
        """Return list of phishing indicators found."""
        return []
