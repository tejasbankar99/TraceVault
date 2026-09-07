"""
TraceVault — Authentication Routes
Handles analyst registration, login, token refresh and current-user retrieval.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.schemas.auth import (
    Token,
    TokenData,
    UserCreate,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ──────────────────────────────────────────────
# Security primitives
# ──────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ALGORITHM = "HS256"


# ──────────────────────────────────────────────
# JWT helpers
# ──────────────────────────────────────────────


def _hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Encode *data* into a signed JWT.  Defaults to settings.access_token_expire_minutes."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def verify_token(token: str) -> TokenData:
    """Decode and validate a JWT, returning a :class:`TokenData` on success."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        user_id: str | None = payload.get("sub")
        username: str | None = payload.get("username")
        role: str | None = payload.get("role")
        if user_id is None:
            raise credentials_exc
        return TokenData(user_id=user_id, username=username, role=role)
    except JWTError:
        raise credentials_exc


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency — resolves the Bearer token to a :class:`User` ORM object."""
    token_data = verify_token(token)
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
    return user


def require_analyst(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Dependency that ensures the caller is an analyst or admin."""
    if current_user.role not in ("analyst", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges — analyst or admin role required",
        )
    return current_user


def require_admin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Dependency that ensures the caller is an admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges — admin role required",
        )
    return current_user


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new analyst account",
)
async def register(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Create a new analyst user account.

    - Validates that the username and email are unique.
    - Hashes the password with bcrypt before persisting.
    """
    # Check uniqueness
    existing = await db.execute(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=_hash_password(payload.password),
        role=payload.role if payload.role in ("analyst", "admin") else "analyst",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("New user registered: %s (role=%s)", user.username, user.role)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=Token,
    summary="Obtain a JWT access token",
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db),
) -> Token:
    """Authenticate with username + password and receive a signed JWT.

    The returned token must be sent as ``Authorization: Bearer <token>`` on
    every subsequent protected request.
    """
    result = await db.execute(select(User).where(User.username == form_data.username))
    user: User | None = result.scalar_one_or_none()

    if not user or not _verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")

    expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "role": user.role},
        expires_delta=expires_delta,
    )

    # Update last-login timestamp
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    logger.info("User logged in: %s", user.username)
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(expires_delta.total_seconds()),
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserResponse:
    """Return profile information for the currently authenticated analyst."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh an existing JWT token",
)
async def refresh_token(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Token:
    """Issue a fresh JWT for the already-authenticated user.

    The old token must still be valid (not expired) for this endpoint to work.
    """
    expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(current_user.id), "username": current_user.username, "role": current_user.role},
        expires_delta=expires_delta,
    )
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(expires_delta.total_seconds()),
        user=UserResponse.model_validate(current_user),
    )
