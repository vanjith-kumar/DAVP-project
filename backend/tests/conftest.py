import pytest
from httpx import AsyncClient

@pytest.fixture
def anyio_backend():
    return 'asyncio'
