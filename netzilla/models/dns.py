from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DNSAnalysis:
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    name_servers: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    ptr_record: Optional[str] = None
    reverse_hostname: Optional[str] = None
    ptr_validation: Optional[str] = None
    dnssec_enabled: bool = False
    propagation_status: str = "N/A"
    ttl_summary: str = "N/A"
    warnings: List[str] = field(default_factory=list)
