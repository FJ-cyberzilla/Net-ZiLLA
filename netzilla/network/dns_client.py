"""
Module for DNS record resolution and analysis.
"""
import logging

import dns.resolver
import dns.reversename

from netzilla.models.dns import DNSAnalysis


class DNSClient:
    def __init__(self, timeout: float = 10.0):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["1.1.1.1"]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.logger = logging.getLogger(__name__)

    async def lookup(self, domain: str) -> DNSAnalysis:
        analysis = DNSAnalysis()

        # Run all lookups concurrently
        import asyncio

        a_task = self.resolve_a(domain)
        mx_task = self.resolve_mx(domain)
        txt_task = self.resolve_txt(domain)
        ns_task = self.resolve_ns(domain)

        results = await asyncio.gather(
            a_task, mx_task, txt_task, ns_task, return_exceptions=True
        )

        # Unpack results with error handling
        analysis.a_records = results[0] if not isinstance(results[0], Exception) else []
        analysis.mx_records = (
            results[1] if not isinstance(results[1], Exception) else []
        )
        analysis.txt_records = (
            results[2] if not isinstance(results[2], Exception) else []
        )
        analysis.name_servers = (
            results[3] if not isinstance(results[3], Exception) else []
        )

        # PTR lookup for first A record if exists
        if analysis.a_records:
            try:
                # Basic reverse lookup
                addr = dns.reversename.from_address(analysis.a_records[0])
                answers = await asyncio.to_thread(self.resolver.resolve, addr, "PTR")
                analysis.ptr_record = str(answers[0])
                analysis.reverse_hostname = analysis.ptr_record
                analysis.ptr_validation = "Valid (basic check)"
            except Exception:
                analysis.ptr_validation = "Failed"
        else:
            analysis.ptr_validation = "No A record to check"

        return analysis

    async def resolve_a(self, domain: str) -> list[str]:
        try:
            answers = self.resolver.resolve(domain, "A")
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers:
            return []

    async def resolve_mx(self, domain: str) -> list[str]:
        try:
            answers = self.resolver.resolve(domain, "MX")
            return [f"{rdata.exchange} (prio:{rdata.preference})" for rdata in answers]
        except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers:
            return []

    async def resolve_txt(self, domain: str) -> list[str]:
        try:
            answers = self.resolver.resolve(domain, "TXT")
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers:
            return []

    async def resolve_ns(self, domain: str) -> list[str]:
        try:
            answers = self.resolver.resolve(domain, "NS")
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers:
            return []
