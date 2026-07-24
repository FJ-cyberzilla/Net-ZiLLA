import re
from typing import List
from dataclasses import dataclass

@dataclass
class PatternMatch:
    type: str
    pattern: str
    matches: list[str]
    confidence: float

class PatternEngine:
    def __init__(self):
        self.phishing_patterns = [
            re.compile(r'(?i)login.*verify'),
            re.compile(r'(?i)account.*secure'),
            re.compile(r'(?i)password.*reset'),
            re.compile(r'(?i)bank.*update'),
            re.compile(r'(?i)paypal.*confirm'),
        ]
        self.malware_patterns = [
            re.compile(r'(?i)\.exe$'),
            re.compile(r'(?i)\.scr$'),
            re.compile(r'(?i)\.bat$'),
            re.compile(r'(?i)download.*file'),
            re.compile(r'(?i)install.*now'),
        ]
        self.tracking_patterns = [
            re.compile(r'(?i)utm_'),
            re.compile(r'(?i)fbclid='),
            re.compile(r'(?i)gclid='),
            re.compile(r'(?i)msclkid='),
        ]
        self.social_engineering_patterns = [
            re.compile(r'(?i)urgent'),
            re.compile(r'(?i)immediate'),
            re.compile(r'(?i)action.*required'),
            re.compile(r'(?i)your.*account'),
            re.compile(r'(?i)suspended'),
            re.compile(r'(?i)limited.*time'),
        ]

    def analyze_text(self, text: str) -> list[PatternMatch]:
        matches = []
        matches.extend(self._check_patterns(text, "phishing", self.phishing_patterns))
        matches.extend(self._check_patterns(text, "malware", self.malware_patterns))
        matches.extend(self._check_patterns(text, "tracking", self.tracking_patterns))
        matches.extend(self._check_patterns(text, "social_engineering", self.social_engineering_patterns))
        return matches

    def _check_patterns(self, text: str, category: str, patterns: list[re.Pattern]) -> list[PatternMatch]:
        matches = []
        for pattern in patterns:
            found = pattern.findall(text)
            if found:
                confidence = self._calculate_confidence(category, found)
                matches.append(PatternMatch(
                    type=category,
                    pattern=pattern.pattern,
                    matches=found,
                    confidence=confidence
                ))
        return matches

    def _calculate_confidence(self, category: str, matches: list[str]) -> float:
        base_confidence = {
            "phishing": 0.8,
            "malware": 0.9,
            "tracking": 0.6,
            "social_engineering": 0.7,
        }

        confidence = base_confidence.get(category, 0.5)

        if len(matches) > 1:
            confidence += 0.1

        for match in matches:
            if match.lower() == match or match.upper() == match:
                confidence += 0.05

        return min(confidence, 1.0)

    def analyze_url(self, url: str) -> list[PatternMatch]:
        matches = []
        if url.startswith("data:"):
            matches.append(PatternMatch("malware", "data_uri", [url], 0.8))
        if url.startswith("javascript:"):
            matches.append(PatternMatch("malware", "javascript_uri", [url], 0.9))
        if url.startswith("vbscript:"):
            matches.append(PatternMatch("malware", "vbscript_uri", [url], 0.9))
        if url.count("%") > 5:
            matches.append(PatternMatch("obfuscation", "excessive_encoding", [url], 0.7))
        return matches
