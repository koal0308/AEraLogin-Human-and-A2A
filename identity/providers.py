"""Human authentication providers.

A provider turns an ALREADY VERIFIED provider credential into a stable
`provider_subject`. Verification itself stays where it is today (the wallet
signature check in server.py / agent/owner_challenges.py); this module never
sees a signature, token or secret.

Only the wallet provider exists in this phase. Google/GitHub are future
providers: their names are reserved so a binding for them cannot be created
by accident before a real, verified implementation exists.
"""
from __future__ import annotations

import re

WALLET = "wallet"

#: Providers that may be bound today.
IMPLEMENTED_PROVIDERS = frozenset({WALLET})

#: Reserved for later phases. Binding is refused until implemented.
FUTURE_PROVIDERS = frozenset({"google", "github"})

_WALLET_RE = re.compile(r"^0x[0-9a-f]{40}$")


class ProviderError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def normalize_subject(provider: str, subject: str) -> str:
    """Return the canonical provider subject or raise ProviderError."""
    if provider not in IMPLEMENTED_PROVIDERS:
        raise ProviderError("unsupported_provider")
    if provider == WALLET:
        return wallet_subject(subject)
    raise ProviderError("unsupported_provider")  # pragma: no cover


def wallet_subject(address: str) -> str:
    """Wallet subject = lowercase 0x address.

    This is the identity format the system already uses everywhere
    (`users.address`, `agents.owner_wallet`, the dashboard session `address`
    claim). No new wallet identity format is introduced.
    """
    value = (address or "").strip().lower()
    if not _WALLET_RE.match(value):
        raise ProviderError("invalid_wallet_address")
    return value
