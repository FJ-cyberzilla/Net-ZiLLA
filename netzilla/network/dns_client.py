import logging
import dns.resolver
import dns.reversename
from typing import Optional, Tuple
from netzilla.models.dns import DNSAnalysis

class DNSClient:
    def __init__(self, timeout: float = 10.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8']
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.logger = logging.getLogger(__name__)

    def lookup(self, domain: str) -> DNSAnalysis:
        analysis = DNSAnalysis()

        # A/AAAA
        try:
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                analysis.a_records.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            self.logger.warning(f"DNS A lookup failed for {domain}")

        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                analysis.aaaa_records.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            self.logger.warning(f"DNS AAAA lookup failed for {domain}")

        # CNAME
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            analysis.cname = str(answers[0].target)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass # CNAME often fails if not present

        # MX
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                analysis.mx_records.append(f"{rdata.exchange} (prio:{rdata.preference})")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            self.logger.warning(f"DNS MX lookup failed for {domain}")

        # NS
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for rdata in answers:
                analysis.name_servers.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            self.logger.warning(f"DNS NS lookup failed for {domain}")

        # TXT
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                analysis.txt_records.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            self.logger.warning(f"DNS TXT lookup failed for {domain}")

        # DNSSEC
        analysis.dnssec_enabled = self._check_dnssec(domain)

        # PTR
        if analysis.a_records:
            ptr_result, error = self.reverse_dns_lookup(analysis.a_records[0])
            if error:
                self.logger.warning(f"Reverse DNS lookup failed for {analysis.a_records[0]}: {error}")
                analysis.ptr_validation = "Failed"
            else:
                analysis.ptr_record = ptr_result
                analysis.reverse_hostname = ptr_result
                analysis.ptr_validation = "Valid (basic check)"
        else:
            analysis.ptr_validation = "No A record to check"

        return analysis

    def reverse_dns_lookup(self, ip: str) -> Tuple[str, Optional[str]]:
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            return str(answers[0]), None
        except Exception as e:
            return "", str(e)

    def _check_dnssec(self, domain: str) -> bool:
        try:
            self.resolver.resolve("_dnskey." + domain, 'TXT')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False
