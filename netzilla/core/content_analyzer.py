from dataclasses import dataclass, field
from typing import List, Dict
import re

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
    inputs: List[FormInput] = field(default_factory=list)

@dataclass
class ContentAnalysis:
    title: str = ""
    meta_description: str = ""
    keywords: List[str] = field(default_factory=list)
    links: List[Link] = field(default_factory=list)
    images: List[Image] = field(default_factory=list)
    scripts: List[Script] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)
    word_count: int = 0
    language: str = "unknown"
    suspicious_elements: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    load_time: float = 0.0
    content_type: str = ""

class ContentAnalyzer:
    def __init__(self, http_client=None, pattern_engine=None, url_parser=None):
        self.http_client = http_client
        self.pattern_engine = pattern_engine
        self.url_parser = url_parser

    def analyze(self, html_content: str, url: str) -> ContentAnalysis:
        analysis = ContentAnalysis()
        
        self._parse_html_content(html_content, analysis, url)
        self._detect_suspicious_elements(analysis, url)
        self._analyze_security_headers(analysis)
        
        return analysis

    def _parse_html_content(self, html: str, analysis: ContentAnalysis, base_url: str):
        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            analysis.title = title_match.group(1).strip()
            
        # ... other extractions ...

    def _detect_suspicious_elements(self, analysis: ContentAnalysis, url: str):
        # ... logic ...
        pass

    def _analyze_security_headers(self, analysis: ContentAnalysis):
        # ... logic ...
        pass
