import pytest
import asyncio
from app.threat_intel.service import ThreatIntelService
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_private_ip_handling():
    service = ThreatIntelService()
    # Mock DB session
    db_mock = AsyncMock()
    
    result = await service.get_ip_reputation(db_mock, "192.168.1.5")
    assert result["status"] == "SKIPPED"
    
    result = await service.get_ip_reputation(db_mock, "10.0.0.1")
    assert result["status"] == "SKIPPED"

@pytest.mark.asyncio
async def test_public_ip_lookup():
    service = ThreatIntelService()
    
    # Let's bypass DB caching for a pure provider test using MockProvider
    provider = service.mock_provider
    res = await provider.lookup_ip("100.0.0.1") # Mock flags 100.* as malicious
    
    assert res is not None
    assert res["is_malicious"] is True
    assert res["reputation_score"] == 100
