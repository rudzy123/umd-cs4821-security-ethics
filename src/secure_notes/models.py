"""Request and response models. Extra fields are rejected."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

_USERNAME = r"^[A-Za-z0-9_]{3,32}$"


def _reject_nul(value: str, label: str) -> str:
    if "\x00" in value:
        raise ValueError(f"{label} contains a disallowed character")
    return value


class RegisterRequest(BaseModel):
    """Account creation. The password is accepted only to hash it."""

    model_config = ConfigDict(extra="forbid")

    username: Annotated[str, Field(pattern=_USERNAME)]
    password: Annotated[str, Field(min_length=12, max_length=128)]

    @field_validator("username", mode="before")
    @classmethod
    def strip_username(cls, value: object) -> object:
        if isinstance(value, str):
            return _reject_nul(value.strip(), "username")
        return value

    @field_validator("password", mode="before")
    @classmethod
    def screen_password(cls, value: object) -> object:
        if isinstance(value, str):
            return _reject_nul(value, "password")
        return value


class LoginRequest(BaseModel):
    """Login body. Length limits keep the hashing step bounded."""

    model_config = ConfigDict(extra="forbid")

    username: Annotated[str, Field(min_length=1, max_length=32)]
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("username", "password", mode="before")
    @classmethod
    def screen_text(cls, value: object) -> object:
        if isinstance(value, str):
            return _reject_nul(value, "field")
        return value


class UserResponse(BaseModel):
    """Public account fields. The password hash is not one of them."""

    id: str
    username: str


class TokenResponse(BaseModel):
    """Bearer token returned once at login."""

    token: str
    token_type: str = "bearer"
    expires_in: int


class NoteCreateRequest(BaseModel):
    """A note. The owner is taken from the session, not from this body."""

    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, Field(min_length=1, max_length=120)]
    body: Annotated[str, Field(min_length=1, max_length=4000)]

    @field_validator("title", "body", mode="before")
    @classmethod
    def screen_note_text(cls, value: object) -> object:
        if isinstance(value, str):
            return _reject_nul(value, "note")
        return value

    @field_validator("title", "body")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if value.strip() == "":
            raise ValueError("must contain text")
        return value


class NoteResponse(BaseModel):
    """Note contents returned only to the authenticated owner."""

    id: str
    title: str
    body: str
    created_at: str
