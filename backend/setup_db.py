import asyncio
from app.database.database import engine
from app.database.models import Base

async def setup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    print("Database created!")

if __name__ == "__main__":
    asyncio.run(setup())
