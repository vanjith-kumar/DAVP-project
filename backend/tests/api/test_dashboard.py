import pytest
from httpx import AsyncClient
from app.main import app
from app.database.models import Alert

@pytest.mark.asyncio
async def test_dashboard_summary(async_client: AsyncClient, admin_token_headers: dict):
    res = await async_client.get("/api/dashboard/summary", headers=admin_token_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "active_alerts" in data
    assert "critical_alerts" in data
    assert "suspicious_ips" in data

@pytest.mark.asyncio
async def test_dashboard_severity_chart(async_client: AsyncClient, admin_token_headers: dict):
    res = await async_client.get("/api/dashboard/alerts-by-severity", headers=admin_token_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
