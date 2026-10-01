from datetime import timedelta, datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import verify_password, create_access_token
from app.core.permissions import get_current_user
from app.database.database import get_db
from app.schemas.auth import Token
from app.schemas.users import User
from app.services.user_service import get_user_by_username
from app.database.models import User as UserModel

router = APIRouter()

@router.post("/login", response_model=Token)
async def login_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Token:
    user = await get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email/username or password",
        )
    elif not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    access_token_expires = timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.id, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.post("/logout")
async def logout():
    # In a stateless JWT approach, logout is typically handled client-side.
    # Future enhancement could include token blocklisting.
    return {"message": "Successfully logged out on client side."}

@router.get("/me", response_model=User)
async def read_current_user(current_user: UserModel = Depends(get_current_user)) -> User:
    return current_user
