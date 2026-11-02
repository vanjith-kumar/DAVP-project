import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.schemas.users import UserCreate
from app.services.user_service import create_user
from app.database.models import RoleEnum
from tests.conftest import TestingSessionLocal

@pytest_asyncio.fixture
async def test_user():
    async with TestingSessionLocal() as db:
        user_in = UserCreate(username="testuser", email="test@example.com", password="password123", role=RoleEnum.ANALYST)
        user = await create_user(db, user_in)
        return user

@pytest.mark.asyncio
async def test_login(test_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/auth/login", data={"username": "testuser", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_login_invalid_password(test_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/auth/login", data={"username": "testuser", "password": "wrong"})
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_read_me(test_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        login_resp = await ac.post("/api/auth/login", data={"username": "testuser", "password": "password123"})
        token = login_resp.json()["access_token"]
        
        response = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
