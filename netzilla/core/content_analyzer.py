from typing import List, Dict, Optional
import re
from dataclasses import dataclass, field

from netzilla.interfaces import ContentAnalysis

@dataclass
class Link:
    url: str
    text: str
    external: bool

@dataclass
class Image:
    src: str
    alt: str

@dataclass
class Script:
    src: str
    inline: bool
    type: str = ""

@dataclass
class FormInput:
    name: str
    type: str

@dataclass
class Form:
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)

class ContentAnalyzer:
    def __init__(self, http_client=None, pattern_engine=None, url_parser=None):
        self.http_client = http_client
        self.pattern_engine = pattern_engine
        self.url_parser = url_parser
def analyze(self, html_content: str, url: str) -> ContentAnalysis:
    # Temporary dictionary to accumulate values
    data = {
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

    self._parse_html_content(html_content, data, url)
    self._detect_suspicious_elements(data, url)
    self._analyze_security_headers(data)

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


    def _parse_html_content(self, html: str, data: dict, base_url: str):
        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        # Note: Title is not in the new ContentAnalysis model, skipping assignment
            
        # ... other extractions ...

    def _detect_suspicious_elements(self, data: dict, url: str):
        # ... logic ...
        pass

    def _analyze_security_headers(self, data: dict):
        # ... logic ...
        pass
