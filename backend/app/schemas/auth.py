"""
app/schemas/auth.py — re-exports auth-related schemas from app.schemas.user
The API routers import Token, TokenData, UserCreate, UserResponse from here.
"""
from app.schemas.user import (  # noqa: F401
    Token,
    TokenData,
    UserCreate,
    UserResponse,
    UserLogin,
    UserUpdate,
    PasswordChange,
)
