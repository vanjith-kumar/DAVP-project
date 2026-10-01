import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.database.database import get_db
from app.database.base import Base
from app.schemas.users import UserCreate
from app.services.user_service import create_user
from app.database.models import RoleEnum

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

@pytest_asyncio.fixture(autouse=True)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def test_user():
    async with TestingSessionLocal() as db:
        user_in = UserCreate(username="testuser", email="test@example.com", password="password123", role=RoleEnum.ANALYST)
        user = await create_user(db, user_in)
        return user

@pytest.mark.asyncio
async def test_login(test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/auth/login", data={"username": "testuser", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_login_invalid_password(test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/api/auth/login", data={"username": "testuser", "password": "wrong"})
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_read_me(test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        login_resp = await ac.post("/api/auth/login", data={"username": "testuser", "password": "password123"})
        token = login_resp.json()["access_token"]
        
        response = await ac.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
