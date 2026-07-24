import asyncio
import sys

import structlog

from netzilla.core.analyzer import Analyzer, NetworkClients, Services
from netzilla.core.content_analyzer import ContentAnalyzer
from netzilla.core.data_enricher import DataEnricher
from netzilla.core.domain_analyzer import DomainAnalyzer
from netzilla.core.url_parser import URLParser
from netzilla.detectors.phishing import PhishingDetectorImplementation
from netzilla.network.cloudflare_intel import CloudflareIntelClient
from netzilla.network.dns_client import DNSClient
from netzilla.network.http_client import CloudflareHTTPClient
from netzilla.network.whois_client import WhoisClient
from netzilla.reports.generator import ReportGenerator

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)

async def run_analysis(url: str):
    # Initialize components
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
        network=NetworkClients(
            dns=dns_client,
            whois=whois_client
        )
    )
    
    analyzer = Analyzer(
        url_detector=URLParser(),
        phishing_detector=PhishingDetectorImplementation(),
        services=services
    )
    
    try:
        result = await analyzer.analyze(url)
        if services.reporter:
            report = services.reporter.generate(result)
            print("\n--- Analysis Report ---")
            print(report)
        else:
            print("\n--- Analysis Result ---")
            print(result)
    finally:
        await analyzer.shutdown()

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    asyncio.run(run_analysis(url))

if __name__ == "__main__":
    main()
