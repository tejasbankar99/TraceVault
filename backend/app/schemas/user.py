"""
TraceVault – User Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ── Request Schemas ────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """Schema for creating a new user account."""
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., description="Unique email address")
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field("", max_length=256)
    role: Literal["admin", "analyst", "viewer"] = Field("analyst")

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


class UserLogin(BaseModel):
    """Schema for user login credentials."""
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(..., description="Username or email address")
    password: str = Field(..., min_length=1)


class UserUpdate(BaseModel):
    """Schema for updating user profile (all fields optional)."""
    model_config = ConfigDict(str_strip_whitespace=True)

    full_name: Optional[str] = Field(None, max_length=256)
    email: Optional[EmailStr] = None
    role: Optional[Literal["admin", "analyst", "viewer"]] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    """Schema for changing a user's password."""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


# ── Response Schemas ───────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """Public user representation returned from API endpoints."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    """JWT authentication token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token TTL in seconds")
    user: UserResponse


class TokenData(BaseModel):
    """Decoded JWT payload data (used internally for auth verification)."""
    username: str
    user_id: uuid.UUID
    role: str
