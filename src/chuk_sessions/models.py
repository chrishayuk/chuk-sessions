# -*- coding: utf-8 -*-
# chuk_sessions/models.py
"""
Pydantic models for CHUK Sessions.

This module contains all Pydantic models used throughout the library for type safety,
validation, and seamless serialization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from .enums import SessionStatus, TokenType


class SessionMetadata(BaseModel):
    """Pure session metadata for grid operations."""

    session_id: str = Field(..., min_length=1, description="Unique session identifier")
    sandbox_id: str = Field(
        ..., min_length=1, description="Sandbox identifier for multi-tenant isolation"
    )
    user_id: Optional[str] = Field(default=None, description="Optional user identifier")
    created_at: Optional[str] = Field(
        default=None, description="ISO 8601 timestamp of session creation"
    )
    expires_at: Optional[str] = Field(
        default=None, description="ISO 8601 timestamp when session expires"
    )
    status: SessionStatus = Field(
        default=SessionStatus.ACTIVE, description="Current session status"
    )
    last_accessed: Optional[str] = Field(
        default=None, description="ISO 8601 timestamp of last access"
    )
    custom_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Extension point for custom data"
    )

    model_config = {
        "use_enum_values": True,  # Serialize enums as their values
        "validate_assignment": True,  # Validate on attribute assignment
        "populate_by_name": True,  # Allow population by field name
    }

    @model_validator(mode="after")
    def set_default_timestamps(self) -> SessionMetadata:
        """Set default timestamps if not provided."""
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if self.created_at is None:
            self.created_at = now_iso
        if self.last_accessed is None:
            self.last_accessed = self.created_at
        return self

    def is_expired(self) -> bool:
        """Return True if the session has passed its expiry timestamp."""
        if not self.expires_at:
            return False
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > expires

    def touch(self) -> None:
        """Refresh the last-accessed timestamp to 'now'."""
        self.last_accessed = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )

    # Backward compatibility methods
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (backward compatible)."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionMetadata:
        """Create from dictionary (backward compatible)."""
        return cls.model_validate(data)


class CSRFTokenInfo(BaseModel):
    """Information extracted from a CSRF token."""

    session_id: str = Field(default="", description="Session ID bound to the token")
    timestamp: int = Field(
        default=0, description="Unix timestamp when token was created"
    )
    token_type: TokenType = Field(
        default=TokenType.HMAC, description="Type of CSRF token"
    )
    user_data: dict[str, Any] = Field(
        default_factory=dict, description="Additional user data in token"
    )
    is_valid: bool = Field(default=True, description="Whether the token is valid")
    error: Optional[str] = Field(
        default=None, description="Error message if token is invalid"
    )

    model_config = {
        "use_enum_values": True,
        "validate_assignment": True,
        "populate_by_name": True,
    }

    @property
    def age_seconds(self) -> int:
        """Get the age of the token in seconds."""
        import time

        return int(time.time()) - self.timestamp

    @property
    def is_expired(self) -> bool:
        """Check if the token is expired based on default max age (1 hour)."""
        return self.age_seconds > 3600

    def is_expired_for_max_age(self, max_age_seconds: int) -> bool:
        """Check if the token is expired for a specific max age."""
        return self.age_seconds > max_age_seconds

    # Backward compatibility method
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (backward compatible)."""
        result = self.model_dump()
        result["age_seconds"] = self.age_seconds
        result["is_expired"] = self.is_expired
        return result


__all__ = [
    "SessionMetadata",
    "CSRFTokenInfo",
]
