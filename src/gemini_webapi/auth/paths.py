"""Filesystem locations and environment-variable names for the auth layer.

Everything the auth layer touches on disk is resolved here, so there is exactly one
place to audit for "where can a credential end up?". Three rules hold for every
path this module returns:

1. **Directories are created 0o700, files 0o600** (POSIX; on Windows the mode call
   is a no-op and the parent directory ACL governs — see :func:`secure_mkdir`).
2. **No secret ever appears in a path.** The cookie cache filename used to embed the
   raw ``__Secure-1PSID`` value in a world-readable temp directory; it is now a
   truncated SHA-256 digest under the auth home. See ADR-0005.
3. **The shared profile is opt-out, not implicit.** ``gemini-web`` reads and writes the
   same Playwright ``storage_state.json`` that ``notebooklm`` owns, because a single
   Google web session backs both tools (ADR-0003). ``GEMINI_AUTH_SHARED=0`` opts out.

Resolution ladder for the storage state, highest precedence first:

===  =============================================  ==================================
#    Source                                         Value
===  =============================================  ==================================
1    ``GEMINI_AUTH_STORAGE``                        explicit file path
2    shared NotebookLM profile (unless opted out)   ``<nblm home>/profiles/<p>/storage_state.json``
3    own profile                                    ``<gemini-web home>/profiles/<p>/storage_state.json``
===  =============================================  ==================================
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# --- Environment-variable names ---------------------------------------------------
# One constant per name, all read through helpers in this module, so a rename is a
# single edit and `grep GEMINI_` finds the whole configuration surface.

#: Base directory for gemini-webapi's own auth material (default ``~/.gemini-webapi``).
GEMINI_HOME_ENV = "GEMINI_HOME"
#: Explicit path to a Playwright ``storage_state.json``; wins over every other source.
GEMINI_AUTH_STORAGE_ENV = "GEMINI_AUTH_STORAGE"
#: Profile name selecting a subdirectory under ``profiles/`` (default ``default``).
GEMINI_AUTH_PROFILE_ENV = "GEMINI_AUTH_PROFILE"
#: Set to a false-ish value to stop sharing NotebookLM's profile directory.
GEMINI_AUTH_SHARED_ENV = "GEMINI_AUTH_SHARED"
#: Set to a false-ish value to stop writing rotated ``__Secure-1PSIDTS`` back to the
#: shared storage state. Leaving it enabled is what keeps the two tools from
#: invalidating each other's session (ADR-0006).
GEMINI_AUTH_WRITEBACK_ENV = "GEMINI_AUTH_WRITEBACK"
#: Legacy override kept for compatibility: directory for the rotated-cookie cache.
GEMINI_COOKIE_PATH_ENV = "GEMINI_COOKIE_PATH"
#: Cookie values passed in directly, read by the CLI and the credential resolver.
GEMINI_SECURE_1PSID_ENV = "GEMINI_SECURE_1PSID"
GEMINI_SECURE_1PSIDTS_ENV = "GEMINI_SECURE_1PSIDTS"
#: NotebookLM's own home override; honoured so a relocated NotebookLM stays shared.
NOTEBOOKLM_HOME_ENV = "NOTEBOOKLM_HOME"

DEFAULT_PROFILE = "default"
STORAGE_STATE_FILENAME = "storage_state.json"
BROWSER_PROFILE_DIRNAME = "browser_profile"

_FALSE_VALUES = frozenset({"0", "false", "no", "off", "n", ""})

# Cache filenames are `.cached_cookies_<digest>.json`; the digest length is a
# security/uniqueness trade-off frozen by test_cookie_cache_path.py. 32 hex chars
# (128 bits) collides never in practice and reveals nothing about the value.
_CACHE_DIGEST_CHARS = 32


def env_flag(name: str, *, default: bool) -> bool:
    """Return the boolean value of environment variable ``name``.

    Unset means ``default``; anything in :data:`_FALSE_VALUES` (case-insensitively)
    means ``False``; every other value means ``True``. Centralised so the shared-profile
    and write-back switches cannot drift into disagreeing about what ``"0"`` means.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in _FALSE_VALUES


def gemini_home() -> Path:
    """Return gemini-webapi's own auth home (``$GEMINI_HOME`` or ``~/.gemini-webapi``)."""
    if raw := os.environ.get(GEMINI_HOME_ENV):
        return Path(raw).expanduser()
    return Path.home() / ".gemini-webapi"


def notebooklm_home() -> Path:
    """Return NotebookLM's home (``$NOTEBOOKLM_HOME`` or ``~/.notebooklm``).

    Mirrors ``notebooklm.paths.get_home_dir``. Duplicating the two-line rule beats
    importing NotebookLM: the shared-profile feature must work whether or not the
    other package is installed, and an optional import that silently changes which
    file is written is worse than a rule stated twice (ADR-0003).
    """
    if raw := os.environ.get(NOTEBOOKLM_HOME_ENV):
        return Path(raw).expanduser()
    return Path.home() / ".notebooklm"


def profile_name(profile: str | None = None) -> str:
    """Return the effective profile name for ``profile``.

    Explicit argument wins over ``$GEMINI_AUTH_PROFILE`` wins over ``"default"``.
    The name is used as a single path segment, so separators and traversal segments
    are rejected rather than sanitised — a silently rewritten profile name would
    read from one file and write to another.
    """
    name = profile or os.environ.get(GEMINI_AUTH_PROFILE_ENV) or DEFAULT_PROFILE
    name = name.strip()
    if not name:
        return DEFAULT_PROFILE
    if name in {".", ".."} or "/" in name or "\\" in name or os.sep in name:
        raise ValueError(f"Invalid profile name {name!r}: must be a single path segment.")
    return name


def sharing_enabled() -> bool:
    """Return whether the NotebookLM profile directory may be used (default ``True``)."""
    return env_flag(GEMINI_AUTH_SHARED_ENV, default=True)


def writeback_enabled() -> bool:
    """Return whether rotated cookies are written back to the storage state (default ``True``)."""
    return env_flag(GEMINI_AUTH_WRITEBACK_ENV, default=True)


@dataclass(frozen=True)
class StorageTarget:
    """The storage-state file the auth layer will read from or write to.

    Attributes
    ----------
    path:
        The ``storage_state.json`` itself.
    source:
        Which ladder rung produced it — ``"env"``, ``"shared"`` or ``"own"``. Reported
        by ``gemini-web auth status`` so a surprising session can be traced to a file.
    shared:
        ``True`` when the file is NotebookLM's, which makes every write a write to
        another tool's state: locked, atomic, and limited to the cookies we own.

    """

    path: Path
    source: str
    shared: bool

    @property
    def profile_dir(self) -> Path:
        """Directory holding the storage state (and, for our own profiles, its siblings)."""
        return self.path.parent

    @property
    def browser_profile_dir(self) -> Path:
        """Persistent Chromium profile directory beside the storage state.

        Deliberately the same ``browser_profile`` directory NotebookLM launches from
        when the target is shared: one interactive login then serves both tools. Two
        processes cannot drive it at once — Chromium holds a lock on the directory —
        which surfaces as a clear "close the other browser" error rather than
        corruption.
        """
        return self.path.parent / BROWSER_PROFILE_DIRNAME


def storage_target(
    profile: str | None = None, *, allow_shared: bool | None = None
) -> StorageTarget:
    """Resolve which storage state to use, without creating anything.

    ``allow_shared`` overrides the ``GEMINI_AUTH_SHARED`` environment switch, which the
    CLI's ``--no-shared`` flag uses. The shared rung applies only when NotebookLM's
    profile directory already exists: sharing means joining a session someone else
    established, never conjuring a NotebookLM tree that its owner never created.
    """
    if raw := os.environ.get(GEMINI_AUTH_STORAGE_ENV):
        return StorageTarget(Path(raw).expanduser(), source="env", shared=False)

    name = profile_name(profile)
    shared_ok = sharing_enabled() if allow_shared is None else allow_shared
    if shared_ok:
        shared_dir = notebooklm_home() / "profiles" / name
        if shared_dir.is_dir():
            return StorageTarget(shared_dir / STORAGE_STATE_FILENAME, source="shared", shared=True)

    own = gemini_home() / "profiles" / name / STORAGE_STATE_FILENAME
    return StorageTarget(own, source="own", shared=False)


def storage_state_lock_path(storage_path: Path) -> Path:
    """Return the sentinel file guarding writes to ``storage_path``.

    ``.storage_state.json.lock`` — byte-for-byte the name NotebookLM derives in
    ``notebooklm._auth.paths._storage_state_lock_path``. The filename *is* the
    cross-tool contract: two processes that pick different sentinel names for one
    storage file do not exclude each other, and the loser's cookie update is lost.
    Changing this string breaks that mutual exclusion (ADR-0006).
    """
    return storage_path.with_name(f".{storage_path.name}.lock")


def cookie_cache_dir() -> Path:
    """Return the directory holding rotated-cookie caches.

    ``$GEMINI_COOKIE_PATH`` still wins, for compatibility with upstream deployments
    that point it at a volume. Otherwise the cache lives under the auth home, not in
    the shared temp directory: on a multi-user host ``/tmp`` (and its Windows
    equivalent) is readable by other accounts, and upstream wrote the raw
    ``__Secure-1PSID`` into the *filename* there (ADR-0005).
    """
    if raw := os.environ.get(GEMINI_COOKIE_PATH_ENV):
        return Path(raw).expanduser()
    return gemini_home() / "cache"


def legacy_cookie_cache_dir() -> Path:
    """Return the pre-fork cache directory, whose filenames leaked the session id.

    Kept so ``gemini-web doctor`` can find and ``gemini-web auth purge`` can delete files an
    older install left behind. Never read as a credential source.
    """
    return Path(tempfile.gettempdir()) / "gemini_webapi"


def cache_digest(secure_1psid: str) -> str:
    """Return the filename-safe digest identifying a session's cache entry."""
    return hashlib.sha256(secure_1psid.encode("utf-8")).hexdigest()[:_CACHE_DIGEST_CHARS]


def cookie_cache_path(secure_1psid: str) -> Path:
    """Return the cache file for the session identified by ``secure_1psid``.

    The value is hashed, never embedded: a directory listing of the cache must not
    hand a reader a working session cookie.
    """
    return cookie_cache_dir() / f".cached_cookies_{cache_digest(secure_1psid)}.json"


def secure_mkdir(path: Path) -> Path:
    """Create ``path`` (and parents) owner-only, and return it.

    Parents are created with the same restrictive mode. On Windows ``chmod`` cannot
    express "owner only", so the call is skipped there and inherited ACLs govern;
    that asymmetry is why :func:`is_group_or_world_readable` reports rather than asserts.
    """
    path = path.expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != "win32":
        # mkdir()'s mode argument is masked by umask, so restate it on the leaf we
        # just created. Parents may be pre-existing and shared (``~``); re-moding
        # those would be an overreach.
        # Best effort: some filesystems (network mounts, FAT) reject chmod outright.
        with contextlib.suppress(OSError):
            path.chmod(0o700)
    return path


def harden_file(path: Path) -> None:
    """Restrict ``path`` to owner read/write, best effort on Windows."""
    with contextlib.suppress(OSError):  # filesystem without usable mode bits
        path.chmod(0o600)


def is_group_or_world_readable(path: Path) -> bool:
    """Return whether ``path``'s mode grants any group/other bit.

    Always ``False`` on Windows, where the mode bits are synthesised and say nothing
    about the real ACL. ``gemini-web doctor`` uses this to warn, not to fail.
    """
    if sys.platform == "win32":
        return False
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))
