"""Module for analyzing HTML content."""

import re
from dataclasses import dataclass, field
from typing import Optional, TypedDict

class AnalysisData(TypedDict):
    has_login_form: bool
    external_domains: list[str]
    mentioned_brands: list[str]
    obfuscated_scripts: bool
    iframe_count: int
    form_actions: list[str]
    risk_indicators: list[str]
    word_count: int
    language: str
    suspicious_elements: list[str]
    security_headers: dict[str, str]
    load_time: float
    content_type: str

from netzilla.core.pattern_engine import PatternEngine
from netzilla.core.url_parser import URLParser
from netzilla.interfaces import ContentAnalysis, HTTPClient


@dataclass
class Link:
    """Represents a link in the content."""

    url: str
    text: str
    external: bool


@dataclass
class Image:
    """Represents an image in the content."""

    src: str
    alt: str


@dataclass
class Script:
    """Represents a script in the content."""

    src: str
    inline: bool
    type: str = ""


@dataclass
class FormInput:
    """Represents a form input in the content."""

    name: str
    type: str


@dataclass
class Form:
    """Represents a form in the content."""

    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)


class ContentAnalyzer:
    """Analyzes HTML content for security threats."""

    def __init__(
        self,
        http_client: Optional[HTTPClient] = None,
        pattern_engine: Optional[PatternEngine] = None,
        url_parser: Optional[URLParser] = None,
    ):
        """Initialize ContentAnalyzer."""
        self.http_client = http_client
        self.pattern_engine = pattern_engine or PatternEngine()
        self.url_parser = url_parser

    def analyze(self, html_content: str, url: str) -> ContentAnalysis:
        """Analyze HTML content and return analysis results."""
        # Temporary dictionary to accumulate values
        data: AnalysisData = {
            "has_login_form": False,
            "external_domains": [],
            "mentioned_brands": [],
            "obfuscated_scripts": False,
            "iframe_count": 0,
            "form_actions": [],
            "risk_indicators": [],
            "word_count": 0,
            "language": "unknown",
            "suspicious_elements": [],
            "security_headers": {},
            "load_time": 0.0,
            "content_type": "",
        }

        self._parse_html_content(html_content, data)
        self._detect_suspicious_elements(data)
        self._analyze_security_headers(data)

        # Integrate PatternEngine
        text_matches = self.pattern_engine.analyze_text(html_content)
        url_matches = self.pattern_engine.analyze_url(url)

        for match in text_matches + url_matches:
            data["risk_indicators"].append(
                f"Pattern found: {match.type} ({match.pattern})"
            )

        return ContentAnalysis(
            has_login_form=data["has_login_form"],
            external_domains=data["external_domains"],
            mentioned_brands=data["mentioned_brands"],
            obfuscated_scripts=data["obfuscated_scripts"],
            iframe_count=data["iframe_count"],
            form_actions=data["form_actions"],
            risk_indicators=data["risk_indicators"],
            word_count=data["word_count"],
            language=data["language"],
            suspicious_elements=data["suspicious_elements"],
            security_headers=data["security_headers"],
            load_time=data["load_time"],
            content_type=data["content_type"],
        )

    def _parse_html_content(self, html: str, data: AnalysisData) -> None:
        """Parse HTML content."""
        # Count iframes
        data["iframe_count"] = len(re.findall(r"<iframe", html, re.IGNORECASE))

        # Check for login forms
        if re.search(r'type=["\']password["\']', html, re.IGNORECASE):
            data["has_login_form"] = True

        # Extract word count (rough)
        clean_text = re.sub(r"<[^>]+>", " ", html)
        data["word_count"] = len(clean_text.split())

    def _detect_suspicious_elements(self, data: AnalysisData) -> None:
        """Detect suspicious elements."""
        if data["iframe_count"] > 2:
            data["suspicious_elements"].append("Multiple iframes detected")
        if data["has_login_form"]:
            data["risk_indicators"].append("Page contains a login form")

    def _analyze_security_headers(self, data: AnalysisData) -> None:
        """Analyze security headers."""
        # Logic to be implemented when headers are available
