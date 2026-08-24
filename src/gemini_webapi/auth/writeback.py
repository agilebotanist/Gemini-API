"""Pushing rotated cookies back into the shared storage state.

``__Secure-1PSIDTS`` rotates: the server issues a new value and the old one stops
working. That is fine for one client and a problem for two. If ``gemini-web`` rotates and
keeps the new token to itself, ``notebooklm``'s copy is now stale and its next call
fails with 401 — a session the user established interactively, broken by a tool they
were not running at the time.

So write-back is not a nicety of the shared-folder design (ADR-0003); it is what makes
it correct (ADR-0006). Every rotation this package performs is merged into the storage
state under the sentinel lock, updating only ``__Secure-1PSID`` / ``__Secure-1PSIDTS``
and only when the file already describes the same session.

``GEMINI_AUTH_WRITEBACK=0`` disables it, for the case where the storage state is
someone else's to manage and staleness is preferable to a write.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import cookie_policy as policy
from . import storage_state as store
from .paths import storage_target, writeback_enabled
from .redaction import fingerprint


def sync_credentials(
    psid: str | None,
    psidts: str | None,
    *,
    expires: float | None = None,
    profile: str | None = None,
    path: Path | None = None,
) -> list[str]:
    """Merge ``psid`` / ``psidts`` into the storage state; return the changed names.

    Returns an empty list — never raises — when write-back is disabled, when there is
    no storage state to update, when the file describes a different session, or when
    the values are already current. Callers are cookie-rotation paths in a background
    task: a failure to persist must degrade to "the other tool will re-login", not
    take down the running client.
    """
    if not writeback_enabled() or not psid:
        return []
    target_path = path or storage_target(profile).path
    if not target_path.exists():
        # Nothing to keep in sync. Creating a storage state from a rotation would
        # invent a credential store the user never asked for, in a directory that may
        # belong to another tool.
        return []
    try:
        return store.update_credentials(
            target_path,
            psid=psid,
            psidts=psidts,
            expires=expires,
            require_matching_psid=True,
        )
    except Exception:  # pragma: no cover - best effort by contract
        return []


def sync_from_jar(jar: Iterable[Any], *, profile: str | None = None) -> list[str]:
    """Extract Gemini's cookies from a ``curl_cffi`` jar and write them back.

    Accepts anything iterable of objects carrying ``name`` / ``value`` / ``expires``
    (``curl_cffi.requests.Cookies.jar``, ``http.cookiejar``) so the HTTP layer's type
    does not leak into the auth layer.
    """
    rows = []
    for cookie in jar:
        name = getattr(cookie, "name", None)
        value = getattr(cookie, "value", None)
        if not isinstance(name, str) or name not in policy.ALLOWED_COOKIE_NAMES:
            continue
        if not isinstance(value, str) or not value:
            continue
        rows.append((name, value, getattr(cookie, "expires", None)))

    values = {name: value for name, value, _ in rows}
    expiries = {name: exp for name, _, exp in rows}
    psid = values.get(policy.PSID)
    psidts = values.get(policy.PSIDTS)
    expires = expiries.get(policy.PSIDTS) or expiries.get(policy.PSID)
    return sync_credentials(
        psid,
        psidts,
        expires=float(expires) if isinstance(expires, (int, float)) and expires > 0 else None,
        profile=profile,
    )


def describe(changed: Iterable[str], psidts: str | None = None) -> str:
    """Return a value-free log line for a write-back result."""
    names = sorted(changed)
    if not names:
        return "storage state already current"
    return f"storage state updated: {', '.join(names)} (psidts={fingerprint(psidts)})"
