"""Domain analysis module for identifying domain-related threats."""
# pylint: disable=too-few-public-methods
from typing import Any, TypedDict

import structlog

from netzilla.network.dns_client import DNSClient
from netzilla.network.whois_client import WhoisClient

logger = structlog.get_logger(__name__)


class DomainFindings(TypedDict):
    threats: list[str]
    warnings: list[str]
    score_bonus: int


class DomainAnalyzer:
    """Analyzes domains for potential threats."""

    def __init__(self, dns_client: DNSClient, whois_client: WhoisClient):
        """Initializes the DomainAnalyzer."""
        self.dns_client = dns_client
        self.whois_client = whois_client

    async def analyze(self, domain: str) -> DomainFindings:
        """Analyzes a domain for threats.

        Args:
            domain: The domain to analyze.

        Returns:
            A dictionary containing threat information.
        """
        findings: DomainFindings = {"threats": [], "warnings": [], "score_bonus": 0}

        # WHOIS check
        try:
            whois_info = await self.whois_client.lookup(domain)
            if whois_info.days_old is not None and whois_info.days_old < 30:
                findings["score_bonus"] += 10
                findings["threats"].append("Domain is very new (less than 30 days)")
            if whois_info.is_newly_registered:
                findings["warnings"].append("Domain was recently registered")
        # pylint: disable=broad-exception-caught
        except Exception as e:
            logger.warning(
                "Failed to perform WHOIS lookup", domain=domain, error=str(e)
            )

        # DNS check
        try:
            # Note: Using DNSClient resolve methods if available
            if hasattr(self.dns_client, "resolve_txt"):
                txt_records = await self.dns_client.resolve_txt(domain)
                if not txt_records:
                    findings["score_bonus"] += 2
                    findings["warnings"].append("No TXT records found")
        # pylint: disable=broad-exception-caught
        except Exception as e:
            logger.warning("Failed to perform DNS lookup", domain=domain, error=str(e))

        return findings
