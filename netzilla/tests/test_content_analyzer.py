import pytest
from netzilla.core.content_analyzer import ContentAnalyzer
from netzilla.interfaces import ContentAnalysis

def test_content_analyzer_basic_analysis():
    analyzer = ContentAnalyzer()
    html = "<html><body><h1>Hello</h1><input type='password'></body></html>"
    url = "http://example.com"
    
    result = analyzer.analyze(html, url)
    
    assert isinstance(result, ContentAnalysis)
    assert result.has_login_form is True
    assert result.word_count > 0
    assert result.iframe_count == 0

def test_content_analyzer_suspicious_elements():
    analyzer = ContentAnalyzer()
    html = "<html><body><iframe></iframe><iframe></iframe><iframe></iframe></body></html>"
    url = "http://example.com"
    
    result = analyzer.analyze(html, url)
    
    assert result.iframe_count == 3
    assert "Multiple iframes detected" in result.suspicious_elements
