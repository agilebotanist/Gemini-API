"""Which cookies the auth layer is allowed to read, keep and write.

A Google login leaves ~40 cookies in a browser profile. Gemini's web endpoints need
**two** of them, so two is what this package handles: ``__Secure-1PSID`` and
``__Secure-1PSIDTS`` on ``.google.com``. Everything else is dropped at the boundary
(ADR-0004).

That is a deliberate minimum-privilege choice with a functional payoff. Upstream
already learned the functional half — loading the full browser jar makes
``RotateCookies`` answer 401, so its browser path keeps only these two names. The
security half is that the material this process holds, caches and writes back is the
smallest set that still works: an accidental disclosure leaks a Gemini session rather
than the whole Google account surface (Gmail, Drive, account recovery).

Rows are also *sanitised* here, not just filtered. A cookie value carrying a newline
or a control character is a header-injection primitive once it reaches an HTTP client,
and a malformed row from a hand-edited storage state should be skipped with a
value-free warning rather than crash a login.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from typing import Any

#: The cookie that identifies the Google session. Without it there is no auth.
PSID = "__Secure-1PSID"
#: The rotating companion. Some accounts never have one, so it is optional
#: everywhere: absent is a valid state, empty-string is not a value.
PSIDTS = "__Secure-1PSIDTS"

#: The complete set of cookie names this package reads, stores or transmits.
ALLOWED_COOKIE_NAMES = frozenset({PSID, PSIDTS})

#: Cookie domains accepted for the names above. Gemini's session cookies are issued
#: host-wide on ``.google.com``; a row claiming ``__Secure-1PSID`` for another domain
#: is either a different product's cookie or something we should not be forwarding.
ALLOWED_COOKIE_DOMAINS = frozenset({".google.com", "google.com"})

#: Control characters that must never appear in a cookie value (CR/LF are the
#: injection vector; NUL breaks C-level HTTP clients).
_FORBIDDEN_VALUE_CHARS = frozenset({"\r", "\n", "\x00", "\t", ";"})

DEFAULT_COOKIE_PATH = "/"


class CookieRowError(ValueError):
    """A storage-state / browser cookie row that cannot be used.

    Carries ``field`` so callers can log *which* part was wrong without logging the
    row itself. Never carries the value.
    """

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"invalid cookie {field}: {reason}")
        self.field = field
        self.reason = reason


def is_allowed(name: Any, domain: Any) -> bool:
    """Return whether a cookie of this ``name`` and ``domain`` may be used.

    Domain matching is exact after normalising the leading dot, deliberately without
    a suffix rule: ``.google.com`` and ``google.com`` are the same issuer, while
    ``evil-google.com`` and ``accounts.google.com`` are not what Gemini's endpoints
    expect and are not needed.
    """
    if name not in ALLOWED_COOKIE_NAMES or not isinstance(domain, str):
        return False
    normalized = domain.lstrip(".").lower()
    return normalized in {d.lstrip(".") for d in ALLOWED_COOKIE_DOMAINS}


def sanitize_row(row: Any, *, require_value: bool = True) -> dict[str, Any]:
    """Return a normalised copy of one cookie row, or raise :class:`CookieRowError`.

    Normalisation is total: the returned dict always has ``name``, ``value``,
    ``domain``, ``path`` and ``expires`` with the right types, so downstream code
    never re-checks. ``expires`` is normalised to a float epoch, with Playwright's
    ``-1`` (session cookie) preserved as ``-1.0``.

    Millisecond expiries are converted to seconds. Browsers and export extensions
    disagree about the unit, and a millisecond value read as seconds puts the expiry
    ~50,000 years out — which silently disables every expiry check downstream.
    """
    if not isinstance(row, Mapping):
        raise CookieRowError("row", f"expected a mapping, got {type(row).__name__}")

    name = row.get("name")
    if not isinstance(name, str) or not name:
        raise CookieRowError("name", "missing or not a non-empty string")

    value = row.get("value")
    if value is None and not require_value:
        value = ""
    if not isinstance(value, str):
        raise CookieRowError("value", "not a string")
    if require_value and not value:
        raise CookieRowError("value", "empty")
    if any(ch in value for ch in _FORBIDDEN_VALUE_CHARS):
        raise CookieRowError("value", "contains a control character or delimiter")

    domain = row.get("domain", ".google.com")
    if not isinstance(domain, str) or not domain:
        raise CookieRowError("domain", "missing or not a non-empty string")

    path = row.get("path", DEFAULT_COOKIE_PATH)
    if not isinstance(path, str) or not path:
        path = DEFAULT_COOKIE_PATH

    expires = _normalize_expires(row.get("expires", row.get("expirationDate")))

    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": expires,
        "httpOnly": bool(row.get("httpOnly", True)),
        "secure": bool(row.get("secure", True)),
        "sameSite": row.get("sameSite") if isinstance(row.get("sameSite"), str) else "None",
    }


def _normalize_expires(raw: Any) -> float:
    """Return ``raw`` as a float epoch in seconds; ``-1`` means a session cookie."""
    if raw is None or raw is True or raw is False:
        return -1.0
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise CookieRowError("expires", "not a number") from None
    if value <= 0:
        return -1.0
    # Anything past ~year 5000 in seconds is a millisecond timestamp in disguise.
    if value > 100_000_000_000:
        value /= 1000.0
    return value


def is_expired(row: Mapping[str, Any], *, now: float | None = None, skew: float = 0.0) -> bool:
    """Return whether a sanitised row's expiry has passed.

    Session cookies (``expires == -1``) are never expired: they live as long as the
    browser context that issued them, which for our purposes is "until the server
    says otherwise". ``skew`` lets callers treat a nearly-expired cookie as gone.
    """
    expires = row.get("expires", -1.0)
    if not isinstance(expires, (int, float)) or expires <= 0:
        return False
    return float(expires) <= (time.time() if now is None else now) + skew


def filter_cookies(
    rows: Iterable[Any],
    *,
    drop_expired: bool = True,
    on_error: Any = None,
) -> list[dict[str, Any]]:
    """Return the allowed, sanitised, de-duplicated cookies from ``rows``.

    De-duplication keeps the **last** row for a ``(name, domain, path)`` identity:
    storage states accumulate observations in write order, so the later one is the
    fresher rotation. Rejected rows are reported through ``on_error(field, reason)``
    when supplied — never by raising, because one bad row in a 40-cookie browser
    capture must not fail a login.
    """
    kept: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        try:
            clean = sanitize_row(row)
        except CookieRowError as exc:
            if on_error is not None:
                on_error(exc.field, exc.reason)
            continue
        if not is_allowed(clean["name"], clean["domain"]):
            continue
        if drop_expired and is_expired(clean):
            if on_error is not None:
                on_error("expires", f"{clean['name']} is expired")
            continue
        kept[(clean["name"], clean["domain"].lstrip("."), clean["path"])] = clean
    return list(kept.values())


def credentials_from_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[str | None, str | None]:
    """Return ``(psid, psidts)`` from sanitised cookie rows.

    When several rows carry the same name — one per Google account index, or one per
    domain spelling — the one with the furthest expiry wins, falling back to the last
    seen. Picking arbitrarily is how a multi-account profile ends up authenticating as
    the wrong account.
    """
    best: dict[str, tuple[float, str]] = {}
    for row in rows:
        name = row.get("name")
        value = row.get("value")
        if name not in ALLOWED_COOKIE_NAMES or not isinstance(value, str) or not value:
            continue
        expires = row.get("expires", -1.0)
        rank = float(expires) if isinstance(expires, (int, float)) and expires > 0 else 0.0
        current = best.get(name)
        if current is None or rank >= current[0]:
            best[name] = (rank, value)
    psid = best.get(PSID, (0.0, None))[1]
    psidts = best.get(PSIDTS, (0.0, None))[1]
    return psid, psidts
