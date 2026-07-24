from urllib.parse import urlparse
from netzilla.models.threats import ThreatAnalysis
from netzilla.network.dns_client import DNSClient
from netzilla.network.whois_client import WhoisClient
from netzilla.utils.logger import Logger # Assuming this exists or should exist

class DomainAnalyzer:
    def __init__(self, logger: Logger, dns_client: DNSClient, whois_client: WhoisClient):
        self.logger = logger
        self.dns_client = dns_client
        self.whois_client = whois_client

    async def analyze(self, parsed_url: urlparse, analysis: ThreatAnalysis) -> int:
        analysis.domain = parsed_url.hostname or ""
        score = 0

        # WHOIS check
        if analysis.whois_info is None:
            try:
                whois_info = await self.whois_client.lookup(parsed_url.hostname or "")
                analysis.whois_info = whois_info
                if whois_info.domain_age in ["Unknown", "Less than 30 days"]:
                    score += 10
                    analysis.warnings.append("Domain is very new, potential risk")
            except Exception as e:
                self.logger.warn(f"Failed to perform WHOIS lookup: {e}")
                score += 5

        # DNS check
        if analysis.dns_info is None:
            try:
                dns_info = await self.dns_client.lookup(parsed_url.hostname or "")
                analysis.dns_info = dns_info
                if not dns_info.txt_records:
                    score += 2
            except Exception as e:
                self.logger.warn(f"Failed to perform DNS lookup: {e}")
                score += 3
        
        return score
