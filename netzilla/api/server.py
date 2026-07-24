"""Net-Zilla API server."""

import asyncio
import os

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel

from netzilla.core.analyzer import Analyzer, NetworkClients, Services
from netzilla.core.content_analyzer import ContentAnalyzer
from netzilla.core.correlation_analyzer import CorrelationAnalyzer
from netzilla.core.data_enricher import DataEnricher
from netzilla.core.domain_analyzer import DomainAnalyzer
from netzilla.core.url_parser import URLParser
from netzilla.detectors.phishing import PhishingDetectorImplementation
from netzilla.detectors.sms_scam import SMSScamDetector
from netzilla.network.cloudflare_intel import CloudflareIntelClient
from netzilla.network.dns_client import DNSClient
from netzilla.network.http_client import CloudflareHTTPClient
from netzilla.network.whois_client import WhoisClient
from netzilla.reports.generator import ReportGenerator


# Pydantic models for requests/responses
class URLAnalyzeRequest(BaseModel):
    """Request model for URL analysis."""

    url: str


class SMSAnalyzeRequest(BaseModel):
    """Request model for SMS analysis."""

    content: str


class BatchAnalyzeRequest(BaseModel):
    """Request model for batch URL analysis."""

    urls: list[str]


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    message: str


# FastAPI App
app = FastAPI(title="Net-Zilla API")


# Global instances (simplified for demo)
def get_analyzer() -> Analyzer:
    """Create and return an analyzer instance."""
    dns_client = DNSClient()
    whois_client = WhoisClient()
    http_client = CloudflareHTTPClient()
    cf_intel = CloudflareIntelClient()

    services = Services(
        content_analyzer=ContentAnalyzer(),
        domain_analyzer=DomainAnalyzer(dns_client, whois_client),
        data_enricher=DataEnricher(dns_client, whois_client, cf_intel),
        http_client=http_client,
        reporter=ReportGenerator(fmt="json"),
        network=NetworkClients(dns=dns_client, whois=whois_client),
    )

    return Analyzer(
        url_detector=URLParser(),
        phishing_detector=PhishingDetectorImplementation(),
        services=services,
    )


# Dependency: Auth
async def verify_token(request: Request) -> dict:
    """Verify authorization token."""
    # For demo, allow if NETZILLA_API_KEY is not set, otherwise check header
    api_key = os.getenv("NETZILLA_API_KEY")
    if not api_key:
        return {"user": "anonymous"}

    token = request.headers.get("Authorization")
    if not token or token != f"Bearer {api_key}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    return {"user": "authenticated_user"}


# Routes
@app.post("/api/v1/analyze/url", dependencies=[Depends(verify_token)])
async def analyze_url(payload: URLAnalyzeRequest):
    """Analyze a single URL."""
    analyzer = get_analyzer()
    try:
        result = await analyzer.analyze(payload.url)
        return result.model_dump()
    finally:
        await analyzer.shutdown()


@app.post("/api/v1/analyze/sms", dependencies=[Depends(verify_token)])
async def analyze_sms(payload: SMSAnalyzeRequest):
    """Analyze SMS content."""
    detector = SMSScamDetector()
    score = detector.analyze(payload.content)
    urls = detector.extract_urls(payload.content)
    tactic = detector.classify_tactic(payload.content)
    return {
        "status": "success",
        "score": score,
        "urls": urls,
        "tactic": tactic,
        "is_scam": score > 50,
    }


@app.post("/api/v1/analyze/batch", dependencies=[Depends(verify_token)])
async def batch_analyze(payload: BatchAnalyzeRequest):
    """Batch analyze URLs."""
    analyzer = get_analyzer()
    try:
        tasks = [analyzer.analyze(url) for url in payload.urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = []
        for res in results:
            if isinstance(res, Exception):
                final_results.append({"error": str(res)})
            else:
                final_results.append(res.model_dump())

        return {"status": "success", "results": final_results}
    finally:
        await analyzer.shutdown()


@app.post("/api/v1/correlate", dependencies=[Depends(verify_token)])
async def correlate_urls(payload: BatchAnalyzeRequest):
    """Correlate multiple URLs."""
    analyzer = get_analyzer()
    correlation_engine = CorrelationAnalyzer()
    try:
        tasks = [analyzer.analyze(url) for url in payload.urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [res for res in results if not isinstance(res, Exception)]

        if not valid_results:
            return {
                "status": "success",
                "message": "No valid analysis results to correlate",
            }

        correlation = correlation_engine.analyze_correlations(valid_results)
        return correlation
    finally:
        await analyzer.shutdown()


@app.post("/correlate", dependencies=[Depends(verify_token)])
async def correlate_urls_new(payload: BatchAnalyzeRequest):
    """Correlate multiple URLs."""
    analyzer = get_analyzer()
    correlation_engine = CorrelationAnalyzer()
    try:
        tasks = [analyzer.analyze(url) for url in payload.urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [res for res in results if not isinstance(res, Exception)]

        if not valid_results:
            return {
                "status": "success",
                "message": "No valid analysis results to correlate",
            }

        # Cast for type checking
        from netzilla.interfaces import AnalysisResult
        typed_results = [r for r in valid_results if isinstance(r, AnalysisResult)]
        
        correlation = correlation_engine.analyze_correlations(typed_results)
        return correlation
    finally:
        await analyzer.shutdown()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
