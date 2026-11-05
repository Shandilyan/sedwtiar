"""Public contracts for users and roles; password hashes are never exposed."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import RoleName


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=12, max_length=256)
    roles: list[RoleName] = Field(default_factory=lambda: [RoleName.VIEWER])

    @field_validator("email")
    @classmethod
    def validate_email_shape(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized.count("@") != 1 or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("email must contain a local part and domain")
        return normalized

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("display_name cannot be blank")
        return normalized

    @field_validator("roles")
    @classmethod
    def require_at_least_one_role(cls, value: list[RoleName]) -> list[RoleName]:
        if not value:
            raise ValueError("at least one role is required")
        return value


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: RoleName
    description: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime
    roles: list[RoleRead]
