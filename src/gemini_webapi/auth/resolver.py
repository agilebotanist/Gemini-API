"""Where credentials come from, in what order, and how to report on them.

One ladder, one place. Every entry point — the CLI, ``GeminiClient``, the init
handshake — asks this module rather than reading environment variables or files on its
own, so "which cookies is it actually using?" has a single answer that
``gemini-web auth status`` can print.

Ladder, highest precedence first:

===  ==================================  ==========================================
#    Source                              Why it ranks there
===  ==================================  ==========================================
1    explicit arguments                   The caller said so; nothing may override it.
2    ``GEMINI_SECURE_1PSID`` / ``…TS``    Deployment configuration, deliberate.
3    storage state (shared or own)        A real login, refreshed by whichever tool
                                          rotated last. See ADR-0003.
4    local browser cookies                Convenience, and only if ``browser-cookie3``
                                          is installed. Reads another program's
                                          database, so it ranks below our own store.
===  ==================================  ==========================================

Rung 4 is *not* implemented here: it lives in
:func:`gemini_webapi.utils.get_access_token`, which tries several cookie jars against
the live endpoint and needs to interleave them with its own cache. This module owns the
offline ladder — the part that decides what a session *should* be before any request is
sent — and exposes rung 3 as :func:`storage_credentials` so the handshake can slot it
in at the right place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import cookie_policy as policy
from . import storage_state as store
from .paths import (
    GEMINI_SECURE_1PSID_ENV,
    GEMINI_SECURE_1PSIDTS_ENV,
    StorageTarget,
    cookie_cache_dir,
    legacy_cookie_cache_dir,
    profile_name,
    sharing_enabled,
    storage_target,
    writeback_enabled,
)
from .redaction import fingerprint, register_secret

#: Human-readable names for the ladder rungs, as printed by ``gemini-web auth status``.
SOURCE_EXPLICIT = "explicit"
SOURCE_ENV = "env"
SOURCE_STORAGE_SHARED = "storage (shared with notebooklm)"
SOURCE_STORAGE_OWN = "storage (own profile)"
SOURCE_STORAGE_ENV = "storage ($GEMINI_AUTH_STORAGE)"


@dataclass(frozen=True)
class Credentials:
    """A resolved Gemini session credential pair and its provenance.

    ``__str__`` and ``__repr__`` are overridden to print fingerprints. That is not
    politeness — a ``Credentials`` object lands in tracebacks, ``pytest`` assertion
    diffs and ``logger.debug(f"{creds}")`` calls, and each of those is a leak if the
    default dataclass repr runs (ADR-0005).
    """

    psid: str
    psidts: str | None
    source: str
    storage_path: Path | None = None

    def __repr__(self) -> str:
        return (
            f"Credentials(psid={fingerprint(self.psid)}, psidts={fingerprint(self.psidts)}, "
            f"source={self.source!r})"
        )

    __str__ = __repr__

    def as_dict(self) -> dict[str, str]:
        """Return the cookie mapping to hand to an HTTP client. Contains real values."""
        cookies = {policy.PSID: self.psid}
        if self.psidts:
            cookies[policy.PSIDTS] = self.psidts
        return cookies

    def summary(self) -> dict[str, object]:
        """Return a value-free description for display."""
        return {
            "source": self.source,
            "psid": fingerprint(self.psid),
            "psidts": fingerprint(self.psidts),
            "storage_path": str(self.storage_path) if self.storage_path else None,
        }


def _env_credentials() -> Credentials | None:
    """Return credentials from ``GEMINI_SECURE_1PSID`` / ``GEMINI_SECURE_1PSIDTS``."""
    psid = (os.environ.get(GEMINI_SECURE_1PSID_ENV) or "").strip()
    if not psid:
        return None
    psidts = (os.environ.get(GEMINI_SECURE_1PSIDTS_ENV) or "").strip() or None
    register_secret(psid, psidts)
    return Credentials(psid=psid, psidts=psidts, source=SOURCE_ENV)


def storage_credentials(
    profile: str | None = None,
    *,
    allow_shared: bool | None = None,
    strict: bool = False,
) -> Credentials | None:
    """Return the credentials held in the resolved storage state, or ``None``.

    ``strict=False`` (the default) is what the init handshake wants: a corrupt file
    should degrade to "try the other cookie sources", because the alternative is a
    hard failure on a path the user may not even be using. The CLI's ``auth status``
    passes ``strict=True`` so it can *report* the corruption.
    """
    target = storage_target(profile, allow_shared=allow_shared)
    state = store.load(target.path, strict=strict)
    psid, psidts = state.credentials
    if not psid:
        return None
    return Credentials(
        psid=psid,
        psidts=psidts,
        source=_storage_source_label(target),
        storage_path=target.path,
    )


def _storage_source_label(target: StorageTarget) -> str:
    if target.source == "env":
        return SOURCE_STORAGE_ENV
    return SOURCE_STORAGE_SHARED if target.shared else SOURCE_STORAGE_OWN


def resolve(
    *,
    psid: str | None = None,
    psidts: str | None = None,
    profile: str | None = None,
    allow_env: bool = True,
    allow_shared: bool | None = None,
) -> Credentials | None:
    """Walk the offline ladder and return the first credentials found.

    ``None`` means "nothing on disk or in the environment" — the caller may still
    reach a session through local browser cookies or a guest handshake, which is why
    this is not an error.
    """
    if psid:
        register_secret(psid, psidts)
        return Credentials(psid=psid, psidts=psidts or None, source=SOURCE_EXPLICIT)
    if allow_env and (env := _env_credentials()) is not None:
        return env
    return storage_credentials(profile, allow_shared=allow_shared)


def storage_cookie_rows(
    profile: str | None = None,
    *,
    allow_shared: bool | None = None,
) -> list[dict[str, object]]:
    """Return the storage state's cookies as sanitised rows, or an empty list.

    The shape :func:`gemini_webapi.utils.get_access_token` wants: it builds its own
    ``curl_cffi`` jars and only needs name/value/domain/path per row. Failure is
    silent by design — this is one candidate among several in the handshake.
    """
    try:
        target = storage_target(profile, allow_shared=allow_shared)
        state = store.load(target.path, strict=False)
    except Exception:  # pragma: no cover - defensive: never break the handshake
        return []
    return list(state.cookies)


def playwright_available() -> tuple[bool, str]:
    """Return whether Playwright can be imported, and a one-line explanation."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, 'not installed - `pip install "gemini-webapi[playwright]"`'
    try:
        from playwright.async_api import async_playwright  # noqa: F401
    except ImportError:  # pragma: no cover - broken partial install
        return False, "installed but the async API is missing"
    return True, "available"


def status(profile: str | None = None, *, allow_shared: bool | None = None) -> dict[str, object]:
    """Return everything ``gemini-web auth status`` and ``gemini-web doctor`` report.

    Value-free by construction: the credential fields are fingerprints, produced by
    :meth:`StorageState.summary` and :meth:`Credentials.summary`, so adding a field
    here cannot accidentally print a cookie.
    """
    name = profile_name(profile)
    target = storage_target(profile, allow_shared=allow_shared)
    try:
        state = store.load(target.path, strict=True)
        storage_summary: dict[str, object] = state.summary()
        storage_error = None
    except store.StorageStateError as exc:
        storage_summary = {"path": str(target.path), "exists": True}
        storage_error = str(exc)

    resolved = resolve(profile=profile, allow_shared=allow_shared)
    available, playwright_note = playwright_available()
    legacy = sorted(p.name for p in _legacy_cache_files())

    return {
        "profile": name,
        "storage_source": target.source,
        "storage_shared": target.shared,
        "storage": storage_summary,
        "storage_error": storage_error,
        "browser_profile": str(target.browser_profile_dir),
        "browser_profile_exists": target.browser_profile_dir.is_dir(),
        "sharing_enabled": sharing_enabled() if allow_shared is None else bool(allow_shared),
        "writeback_enabled": writeback_enabled(),
        "resolved": resolved.summary() if resolved else None,
        "cookie_cache_dir": str(cookie_cache_dir()),
        "legacy_cache_files": legacy,
        "playwright": playwright_note,
        "playwright_available": available,
        "env_credentials": _env_credentials() is not None,
    }


def _legacy_cache_files() -> list[Path]:
    """Return pre-fork cache files, whose names embed the session cookie (ADR-0005)."""
    directory = legacy_cookie_cache_dir()
    try:
        return [p for p in directory.glob(".cached_cookies_*.json") if p.is_file()]
    except OSError:  # pragma: no cover - unreadable temp dir
        return []
