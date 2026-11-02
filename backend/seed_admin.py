import asyncio
from app.database.database import AsyncSessionLocal
from app.database.models import User, RoleEnum
from app.core.security import get_password_hash

async def seed():
    async with AsyncSessionLocal() as session:
        admin = User(
            username="admin",
            email="admin@securelog.local",
            password_hash=get_password_hash("admin123"),
            role=RoleEnum.ADMIN,
            is_active=True
        )
        session.add(admin)
        await session.commit()
    print("Admin user created (admin / admin123)")

if __name__ == "__main__":
    asyncio.run(seed())
