import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.main import app
from app.database.database import get_db
from app.database.base import Base
from app.database.models import User, RoleEnum
from app.core.security import create_access_token, get_password_hash

TEST_DB_FILE = os.path.join(os.path.dirname(__file__), "test.db")
TEST_DATABASE_URL = f"sqlite+aiosqlite:///{TEST_DB_FILE}"

test_engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest_asyncio.fixture(autouse=True)
async def init_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    # Seed default admin user (id=1) for tests
    async with TestingSessionLocal() as session:
        admin = User(
            id=1,
            username="admin",
            email="admin@securelog.local",
            password_hash=get_password_hash("admin123"),
            role=RoleEnum.ADMIN,
            is_active=True
        )
        session.add(admin)
        await session.commit()
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.fixture
def admin_token_headers():
    token = create_access_token(subject="1")
    return {"Authorization": f"Bearer {token}"}
