"""Credential handling for gemini-webapi: where sessions come from and how they are kept.

This package is the fork's main addition to upstream (see ``FORK.md``). It exists
because the upstream auth story — read cookies out of a local browser's database, or
paste them by hand — cannot recover from an expiry without a human, and because the
credentials involved deserve to be handled like credentials.

What is here:

==========================  =================================================
Module                      Responsibility
==========================  =================================================
:mod:`.paths`               Every filesystem location and env-var name
:mod:`.redaction`           Fingerprints, and scrubbing values out of output
:mod:`.cookie_policy`       Which cookies are allowed; row sanitisation
:mod:`.locking`             Cross-process lock shared with ``notebooklm``
:mod:`.storage_state`       Reading/writing the Playwright session file
:mod:`.writeback`           Pushing rotated cookies back to the shared file
:mod:`.resolver`            The credential ladder, and status reporting
:mod:`.playwright_login`    Interactive login and headless refresh
==========================  =================================================

The architecture decisions behind them are recorded in ``docs/adr/``. Start with
ADR-0002 (why Playwright), ADR-0003 (why the shared folder), ADR-0004 (why two
cookies) and ADR-0005 (secret hygiene).
"""

from __future__ import annotations

from .cookie_policy import (
    ALLOWED_COOKIE_DOMAINS,
    ALLOWED_COOKIE_NAMES,
    PSID,
    PSIDTS,
    CookieRowError,
    credentials_from_rows,
    filter_cookies,
    is_allowed,
    is_expired,
    sanitize_row,
)
from .locking import LockTimeoutError, file_lock
from .paths import (
    DEFAULT_PROFILE,
    GEMINI_AUTH_PROFILE_ENV,
    GEMINI_AUTH_SHARED_ENV,
    GEMINI_AUTH_STORAGE_ENV,
    GEMINI_AUTH_WRITEBACK_ENV,
    GEMINI_HOME_ENV,
    StorageTarget,
    cookie_cache_path,
    gemini_home,
    legacy_cookie_cache_dir,
    notebooklm_home,
    profile_name,
    secure_mkdir,
    storage_state_lock_path,
    storage_target,
    writeback_enabled,
)
from .playwright_login import (
    LoginError,
    LoginPlan,
    LoginResult,
    capture,
    ensure_playwright,
    purge_legacy_cache,
    run_login,
)
from .redaction import (
    cookie_summary,
    fingerprint,
    register_secret,
    scrub,
    scrub_record,
)
from .resolver import (
    Credentials,
    playwright_available,
    resolve,
    status,
    storage_cookie_rows,
    storage_credentials,
)
from .storage_state import (
    StorageState,
    StorageStateError,
    clear_credentials,
    update_credentials,
)
from .writeback import sync_credentials, sync_from_jar

__all__ = [
    "ALLOWED_COOKIE_DOMAINS",
    "ALLOWED_COOKIE_NAMES",
    "DEFAULT_PROFILE",
    "GEMINI_AUTH_PROFILE_ENV",
    "GEMINI_AUTH_SHARED_ENV",
    "GEMINI_AUTH_STORAGE_ENV",
    "GEMINI_AUTH_WRITEBACK_ENV",
    "GEMINI_HOME_ENV",
    "PSID",
    "PSIDTS",
    "CookieRowError",
    "Credentials",
    "LockTimeoutError",
    "LoginError",
    "LoginPlan",
    "LoginResult",
    "StorageState",
    "StorageStateError",
    "StorageTarget",
    "capture",
    "clear_credentials",
    "cookie_cache_path",
    "cookie_summary",
    "credentials_from_rows",
    "ensure_playwright",
    "file_lock",
    "filter_cookies",
    "fingerprint",
    "gemini_home",
    "is_allowed",
    "is_expired",
    "legacy_cookie_cache_dir",
    "notebooklm_home",
    "playwright_available",
    "profile_name",
    "purge_legacy_cache",
    "register_secret",
    "resolve",
    "run_login",
    "sanitize_row",
    "scrub",
    "scrub_record",
    "secure_mkdir",
    "status",
    "storage_cookie_rows",
    "storage_credentials",
    "storage_state_lock_path",
    "storage_target",
    "sync_credentials",
    "sync_from_jar",
    "update_credentials",
    "writeback_enabled",
]
