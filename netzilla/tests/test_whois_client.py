import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, UTC, timedelta
from netzilla.network.whois_client import WhoisClient
from netzilla.interfaces import DomainInfo

@pytest.mark.asyncio
async def test_whois_client_lookup_success():
    client = WhoisClient()
    
    # Mock whois.whois
    mock_whois_data = MagicMock()
    mock_whois_data.registrar = "Example Registrar"
    mock_whois_data.creation_date = datetime.now(UTC) - timedelta(days=50)
    mock_whois_data.expiration_date = datetime.now(UTC) + timedelta(days=365)
    mock_whois_data.name_servers = ["ns1.example.com", "ns2.example.com"]
    
    with patch("whois.whois", return_value=mock_whois_data):
        result = await client.lookup("example.com")
        
    assert isinstance(result, DomainInfo)
    assert result.domain == "example.com"
    assert result.registrar == "Example Registrar"
    assert result.days_old == 50
    assert result.is_newly_registered is False
    assert len(result.nameservers) == 2
