"""
Pattern matching engine for detecting threats in text and URLs.

This module provides the `PatternEngine` class, which uses regular expressions
to classify text into categories like phishing, malware, tracking, and
social engineering, as well as `analyze_url` for URL-specific threat detection.
"""
import re
from dataclasses import dataclass


@dataclass
class PatternMatch:
    """
    Represents a detected pattern match.

    Attributes:
        type (str): The category of the threat (e.g., 'phishing').
        pattern (str): The regex pattern that caused the match.
        matches (list[str]): The actual strings found that matched the pattern.
        confidence (float): A score between 0.0 and 1.0 indicating confidence.
    """

    type: str
    pattern: str
    matches: list[str]
    confidence: float


class PatternEngine:
    """
    Engine for detecting threats based on pre-defined regex patterns.

    Attributes:
        phishing_patterns (list[re.Pattern[str]]): Patterns indicative of phishing.
        malware_patterns (list[re.Pattern[str]]): Patterns indicative of malware.
        tracking_patterns (list[re.Pattern[str]]): Patterns indicative of URL tracking.
        social_engineering_patterns (list[re.Pattern[str]]): Patterns indicative of social engineering.
    """

    def __init__(self) -> None:
        """Initialize the PatternEngine with default regex patterns."""
        self.phishing_patterns = [
            re.compile(r"(?i)login.*verify"),
            re.compile(r"(?i)account.*secure"),
            re.compile(r"(?i)password.*reset"),
            re.compile(r"(?i)bank.*update"),
            re.compile(r"(?i)paypal.*confirm"),
        ]
        self.malware_patterns = [
            re.compile(r"(?i)\.exe$"),
            re.compile(r"(?i)\.scr$"),
            re.compile(r"(?i)\.bat$"),
            re.compile(r"(?i)download.*file"),
            re.compile(r"(?i)install.*now"),
        ]
        self.tracking_patterns = [
            re.compile(r"(?i)utm_"),
            re.compile(r"(?i)fbclid="),
            re.compile(r"(?i)gclid="),
            re.compile(r"(?i)msclkid="),
        ]
        self.social_engineering_patterns = [
            re.compile(r"(?i)urgent"),
            re.compile(r"(?i)immediate"),
            re.compile(r"(?i)action.*required"),
            re.compile(r"(?i)your.*account"),
            re.compile(r"(?i)suspended"),
            re.compile(r"(?i)limited.*time"),
        ]

    def analyze_text(self, text: str) -> list[PatternMatch]:
        """
        Analyze text for known threats across all categories.

        Args:
            text (str): The input text to analyze.

        Returns:
            list[PatternMatch]: A list of detected patterns.
        """
        matches = []
        matches.extend(self._check_patterns(text, "phishing", self.phishing_patterns))
        matches.extend(self._check_patterns(text, "malware", self.malware_patterns))
        matches.extend(self._check_patterns(text, "tracking", self.tracking_patterns))
        matches.extend(
            self._check_patterns(
                text, "social_engineering", self.social_engineering_patterns
            )
        )
        return matches

    def _check_patterns(
        self, text: str, category: str, patterns: list[re.Pattern[str]]
    ) -> list[PatternMatch]:
        """
        Helper to check text against a list of patterns and create PatternMatch objects.

        Args:
            text (str): Input text.
            category (str): Name of the threat category.
            patterns (list[re.Pattern]): List of compiled regex patterns.

        Returns:
            list[PatternMatch]: List of match objects.
        """
        matches = []
        for pattern in patterns:
            found = pattern.findall(text)
            if found:
                confidence = self._calculate_confidence(category, found)
                matches.append(
                    PatternMatch(
                        type=category,
                        pattern=pattern.pattern,
                        matches=found,
                        confidence=confidence,
                    )
                )
        return matches

    def _calculate_confidence(self, category: str, matches: list[str]) -> float:
        """
        Calculate confidence based on match count and characteristics.

        Args:
            category (str): Threat category name.
            matches (list[str]): List of strings that matched the pattern.

        Returns:
            float: Confidence score (0.0 to 1.0).
        """
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
        """
        Analyze a URL for potentially malicious characteristics.

        Args:
            url (str): The URL to analyze.

        Returns:
            list[PatternMatch]: A list of detected threats related to the URL structure.
        """
        matches = []
        if url.startswith("data:"):
            matches.append(PatternMatch("malware", "data_uri", [url], 0.8))
        if url.startswith("javascript:"):
            matches.append(PatternMatch("malware", "javascript_uri", [url], 0.9))
        if url.startswith("vbscript:"):
            matches.append(PatternMatch("malware", "vbscript_uri", [url], 0.9))
        if url.count("%") > 5:
            matches.append(
                PatternMatch("obfuscation", "excessive_encoding", [url], 0.7)
            )
        return matches
