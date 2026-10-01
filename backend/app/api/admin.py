from fastapi import APIRouter, Depends
from app.core.permissions import get_current_active_admin
from app.schemas.users import User

router = APIRouter()

@router.get("/users")
async def get_all_users(current_user: User = Depends(get_current_active_admin)):
    return {"message": "Admin user management functionality will be implemented in later phases."}
