import pytest
from unittest.mock import MagicMock, AsyncMock
import dns.resolver
from netzilla.network.dns_client import DNSClient

@pytest.mark.asyncio
async def test_dns_client_resolve_a_success():
    client = DNSClient()
    # Mock dns.resolver.resolve
    client.resolver.resolve = MagicMock()
    
    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "1.2.3.4"
    client.resolver.resolve.return_value = [mock_rdata]
    
    results = await client.resolve_a("example.com")
    
    assert results == ["1.2.3.4"]
    client.resolver.resolve.assert_called_with("example.com", "A")

@pytest.mark.asyncio
async def test_dns_client_resolve_a_no_answer():
    client = DNSClient()
    # Mock dns.resolver.resolve to raise exception
    client.resolver.resolve = MagicMock(side_effect=dns.resolver.NoAnswer)
    
    results = await client.resolve_a("example.com")
    
    assert results == []
