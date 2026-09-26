"""Abuse protection for the public A2A gateway.

WHY IN MEMORY AND NOT SQLITE
----------------------------
`agent/ratelimit.py` exists and is SQLite-backed, but it is deliberately NOT
reused here. It performs a database write on every single call, which on a
public, unauthenticated endpoint turns the rate limiter itself into the cheapest
available denial-of-service vector: an attacker would force one disk write per
request precisely when we are trying to shed load. A rate limiter must be
cheaper than the work it protects.

This implementation is therefore pure in-process state: a dict of token buckets,
O(1) per check, no I/O, no lock contention beyond a single mutex.

Consequences, stated honestly rather than glossed over:

  * Limits are PER PROCESS. The service currently runs as a single uvicorn
    worker (`uvicorn.run(app, ...)` with no `workers=` argument), so per-process
    and global are the same thing today. If the deployment is ever scaled to N
    workers, the effective ceiling becomes N x the configured rate. That is
    documented, asserted by a test, and must be revisited before scaling out.
  * State is lost on restart. For abuse protection this is acceptable: a
    restart is not an attacker-controllable event.

MEMORY IS ITSELF AN ATTACK SURFACE
----------------------------------
A dict keyed by client IP is unbounded by definition, and an attacker with a
large address pool could exhaust memory. The bucket table is therefore capped
(`MAX_TRACKED_KEYS`) with cheapest-first eviction of idle buckets. Evicting an
idle bucket is safe: a bucket that has fully refilled carries no information,
because recreating it yields exactly the same state.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

# --- scopes -----------------------------------------------------------------
SCOPE_GLOBAL = "global"
SCOPE_PEER = "peer"
SCOPE_AGENT = "agent"

#: Per-credential bucket. An authenticated peer is a *known* caller, so it gets
#: a more generous allowance than an anonymous source address -- but it gets its
#: own bucket rather than an exemption. Authentication identifies a caller; it
#: does not make that caller harmless, and a compromised credential is exactly
#: the case where a limit matters most.
#:
#: This is an ADDITIONAL dimension. The global and per-source buckets still
#: apply to authenticated traffic, so no credential can be used to bypass the
#: protection of the service as a whole.
SCOPE_CREDENTIAL = "credential"

#: Upper bound on tracked buckets per scope, so the limiter cannot be used to
#: exhaust memory. Exceeding it evicts fully-refilled (i.e. stateless) buckets.
MAX_TRACKED_KEYS = 10_000


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Limit:
    """A token bucket specification.

    `rate` is the sustained refill in requests per second; `burst` is the bucket
    capacity, i.e. how many requests may arrive back-to-back before the
    sustained rate starts to bite.
    """

    rate: float
    burst: float

    @property
    def retry_after(self) -> int:
        """Whole seconds a caller should wait for one token to become available."""
        if self.rate <= 0:
            return 60
        return max(1, int(round(1.0 / self.rate)))


def load_limits() -> dict[str, Limit]:
    """Read the configured limits. Conservative, and all eight are tunable."""
    return {
        SCOPE_GLOBAL: Limit(
            rate=_env_float("AERA_A2A_GLOBAL_RATE", 20.0),
            burst=_env_float("AERA_A2A_GLOBAL_BURST", 40.0),
        ),
        SCOPE_PEER: Limit(
            rate=_env_float("AERA_A2A_PEER_RATE", 1.0),
            burst=_env_float("AERA_A2A_PEER_BURST", 10.0),
        ),
        SCOPE_AGENT: Limit(
            rate=_env_float("AERA_A2A_AGENT_RATE", 2.0),
            burst=_env_float("AERA_A2A_AGENT_BURST", 15.0),
        ),
        # Higher than the anonymous per-source limit because the caller is
        # known and revocable, but still finite and still below the global cap.
        SCOPE_CREDENTIAL: Limit(
            rate=_env_float("AERA_A2A_CREDENTIAL_RATE", 5.0),
            burst=_env_float("AERA_A2A_CREDENTIAL_BURST", 30.0),
        ),
    }


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of one check. `scope` names which limit bit, for the audit log."""

    allowed: bool
    scope: Optional[str] = None
    retry_after: int = 0
    #: Tokens left in the bucket that was checked, for observability only.
    remaining: float = 0.0

    def __bool__(self) -> bool:
        return self.allowed


ALLOWED = RateLimitDecision(allowed=True)


class RateLimiter:
    """Token-bucket limiter over three independent scopes.

    The scopes are genuinely independent: exhausting the per-peer bucket does
    not consume global or per-agent tokens, so one noisy caller cannot deny
    service to everyone else by draining a shared counter.
    """

    def __init__(self, limits: Optional[dict[str, Limit]] = None,
                 *, max_keys: int = MAX_TRACKED_KEYS) -> None:
        self.limits = limits or load_limits()
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    # -- introspection -------------------------------------------------------
    def limit_for(self, scope: str) -> Limit:
        return self.limits[scope]

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._buckets)

    def reset(self) -> None:
        """Drop all state. Used by tests and by nothing else."""
        with self._lock:
            self._buckets.clear()

    # -- the actual check ----------------------------------------------------
    def check(self, scope: str, key: str, *, now: Optional[float] = None,
              cost: float = 1.0) -> RateLimitDecision:
        """Consume one token from (scope, key). O(1), no I/O."""
        limit = self.limits[scope]
        current = now if now is not None else time.monotonic()
        composite = (scope, key)

        with self._lock:
            bucket = self._buckets.get(composite)
            if bucket is None:
                self._evict_if_needed(current)
                bucket = _Bucket(tokens=limit.burst, updated=current)
                self._buckets[composite] = bucket
            else:
                elapsed = max(0.0, current - bucket.updated)
                bucket.tokens = min(limit.burst, bucket.tokens + elapsed * limit.rate)
                bucket.updated = current

            if bucket.tokens < cost:
                deficit = cost - bucket.tokens
                wait = deficit / limit.rate if limit.rate > 0 else 60.0
                return RateLimitDecision(
                    allowed=False, scope=scope,
                    retry_after=max(1, int(wait) + (1 if wait % 1 else 0)),
                    remaining=bucket.tokens)

            bucket.tokens -= cost
            return RateLimitDecision(allowed=True, scope=scope,
                                     remaining=bucket.tokens)

    def _evict_if_needed(self, now: float) -> None:
        """Bound memory. Caller must hold the lock."""
        if len(self._buckets) < self._max_keys:
            return
        # A bucket that has fully refilled holds no information: deleting it and
        # recreating it produces an identical bucket. Drop those first.
        for composite, bucket in list(self._buckets.items()):
            limit = self.limits[composite[0]]
            elapsed = max(0.0, now - bucket.updated)
            if min(limit.burst, bucket.tokens + elapsed * limit.rate) >= limit.burst:
                del self._buckets[composite]
        if len(self._buckets) < self._max_keys:
            return
        # Still full: every bucket is actively rate limited. Evict the oldest,
        # which is the closest to refilling anyway.
        oldest = sorted(self._buckets.items(), key=lambda kv: kv[1].updated)
        for composite, _ in oldest[: max(1, self._max_keys // 10)]:
            self._buckets.pop(composite, None)


#: Process-wide limiter used by the gateway routes.
_limiter: Optional[RateLimiter] = None
_limiter_lock = threading.Lock()


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        with _limiter_lock:
            if _limiter is None:
                _limiter = RateLimiter()
    return _limiter


def reset_limiter() -> None:
    """Rebuild the limiter, picking up current environment values."""
    global _limiter
    with _limiter_lock:
        _limiter = RateLimiter()


# --- client source identification -------------------------------------------
def trusted_proxies() -> frozenset[str]:
    """Proxy addresses whose forwarding headers we are willing to believe.

    Empty by default. An empty set means forwarded headers are ignored entirely.
    """
    raw = os.getenv("AERA_A2A_TRUSTED_PROXIES", "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def client_source(request) -> str:
    """Determine the rate-limit key for an UNAUTHENTICATED external peer.

    This is a network source, not an identity. With `auth=none` we have no
    cryptographic evidence of who the caller is, so this value must never be
    treated as a verified peer, a trusted peer, or an AEra agent.

    `X-Forwarded-For` is attacker-controlled: any client can send it. It is
    therefore honoured ONLY when the immediate peer is an explicitly configured
    trusted proxy. Otherwise the direct connection address is used.
    """
    direct = getattr(getattr(request, "client", None), "host", None) or "unknown"

    proxies = trusted_proxies()
    if not proxies:
        return direct

    # The immediate peer must itself be a trusted proxy. Without this check any
    # caller could send X-Forwarded-For and get a fresh bucket per request,
    # which is precisely the bypass the trusted-proxy list exists to prevent.
    if direct not in proxies:
        return direct

    forwarded = None
    try:
        forwarded = request.headers.get("x-forwarded-for")
    except AttributeError:  # pragma: no cover - defensive
        forwarded = None
    if not forwarded:
        return direct

    # Right-to-left: the last entry not contributed by a trusted proxy is the
    # closest thing to a real client address that we can justify believing.
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    for candidate in reversed(candidates):
        if candidate not in proxies:
            return candidate[:64]
    return direct
