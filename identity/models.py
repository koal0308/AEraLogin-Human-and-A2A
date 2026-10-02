"""Human Identity data model."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

HUMAN_ID_PREFIX = "did:aera:human:"

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
HUMAN_STATUSES = frozenset({STATUS_ACTIVE, STATUS_DISABLED})


@dataclass(frozen=True)
class HumanIdentity:
    human_id: str
    status: str
    created_at: str
    updated_at: str

    @property
    def is_active(self) -> bool:
        return self.status == STATUS_ACTIVE


@dataclass(frozen=True)
class ProviderBinding:
    """One authentication provider account bound to a Human Identity.

    `provider_subject` is the stable provider-specific identifier (for the
    wallet provider: the lowercase 0x address). E-mail is optional metadata and
    is never used as a key.
    """
    id: int
    human_id: str
    provider: str
    provider_subject: str
    email: Optional[str]
    email_verified: bool
    created_at: str
    last_login_at: Optional[str]
