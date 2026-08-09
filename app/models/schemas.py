from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
)


# ============================================================
# AUTHENTICATION
# ============================================================

class RegisterRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=100,
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=72,
    )


class LoginRequest(BaseModel):
    email: EmailStr

    password: str = Field(
        min_length=1,
        max_length=72,
    )


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ============================================================
# USER
# ============================================================

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class MeResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class APIKeyResponse(BaseModel):
    api_key: str


# ============================================================
# DETECTION
# ============================================================

class DetectionRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=4096,
    )

    body: str = Field(
        default="",
        max_length=100000,
    )

    headers: dict[str, str] = Field(
        default_factory=dict,
    )


class DetectionResponse(BaseModel):
    detected: bool

    attacks: list[str] = Field(
        default_factory=list,
    )

    score: int = Field(
        ge=0,
        le=100,
    )

    level: str

    blocked: bool

    reason: str