from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from app.database.models import RoleEnum

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: RoleEnum = RoleEnum.ANALYST
    is_active: bool = True

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[RoleEnum] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

class UserInDBBase(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

class User(UserInDBBase):
    pass
