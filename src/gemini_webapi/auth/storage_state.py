"""Reading and writing the Playwright ``storage_state.json``.

The storage state is the file a Playwright login leaves behind: ``{"cookies": [...],
"origins": [...]}``. It is this package's credential store, and — when the shared
profile is in use — it is *also* NotebookLM's, which shapes every rule below
(ADR-0003):

* **Unknown top-level keys are preserved.** NotebookLM keeps account metadata under
  its own key. A writer that rebuilt the document from the cookies it cares about
  would silently delete another tool's state.
* **Writes replace only what we own.** A save merges our two cookies into the existing
  document; the other ~40 cookies stay exactly as they were, byte for byte.
* **Writes are atomic, locked and 0600.** Temp file in the same directory, exclusive
  create, then :func:`os.replace`. A crash mid-write leaves the old file intact rather
  than a truncated one — losing a credential store to a power cut means re-doing an
  interactive browser login.
* **Reads are tolerant, and never fatal by default.** A missing file is "not logged
  in", not an error. A corrupt file *is* an error, because silently treating it as
  empty is how a user ends up wondering why their login "did not stick".
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gemini_webapi.exceptions import AuthError

from . import cookie_policy as policy
from .locking import file_lock
from .paths import (
    harden_file,
    is_group_or_world_readable,
    secure_mkdir,
    storage_state_lock_path,
)
from .redaction import fingerprint, register_secret

#: Top-level keys this package understands. Everything else found in the document is
#: copied through untouched.
KNOWN_KEYS = frozenset({"cookies", "origins"})


class StorageStateError(AuthError):
    """The storage state exists but cannot be used (unreadable or malformed)."""


@dataclass(frozen=True)
class StorageState:
    """A loaded storage state plus where it came from.

    ``document`` is the raw parsed JSON, kept whole so :func:`save` can write back a
    superset of what it read. ``cookies`` is the filtered, sanitised projection of the
    two cookies this package uses — the only cookie data the rest of the code sees.
    """

    path: Path
    document: dict[str, Any] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    exists: bool = False

    @property
    def credentials(self) -> tuple[str | None, str | None]:
        """Return ``(__Secure-1PSID, __Secure-1PSIDTS)``, either possibly ``None``."""
        return policy.credentials_from_rows(self.cookies)

    @property
    def psid(self) -> str | None:
        return self.credentials[0]

    @property
    def psidts(self) -> str | None:
        return self.credentials[1]

    def summary(self) -> dict[str, Any]:
        """Return a value-free description, safe to print or log.

        This is what ``gemini-web auth status`` renders. Everything here is either a
        count, a path, a timestamp or a fingerprint — by construction, not by the
        caller remembering to redact.
        """
        psid, psidts = self.credentials
        rows = {row["name"]: row for row in self.cookies}
        psid_row = rows.get(policy.PSID)
        psidts_row = rows.get(policy.PSIDTS)
        return {
            "path": str(self.path),
            "exists": self.exists,
            "total_cookies": len(self.document.get("cookies", []))
            if isinstance(self.document.get("cookies"), list)
            else 0,
            "usable_cookies": len(self.cookies),
            "psid": fingerprint(psid),
            "psidts": fingerprint(psidts),
            "psid_expires": _iso(psid_row.get("expires") if psid_row else None),
            "psidts_expires": _iso(psidts_row.get("expires") if psidts_row else None),
            "foreign_keys": sorted(set(self.document) - KNOWN_KEYS),
            "world_readable": is_group_or_world_readable(self.path),
            "modified": _iso(_mtime(self.path)),
        }


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _iso(epoch: Any) -> str | None:
    """Return an ISO-8601 UTC string for an epoch, or ``None`` for absent/session."""
    if not isinstance(epoch, (int, float)) or epoch <= 0:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def load(path: Path, *, strict: bool = True, register: bool = True) -> StorageState:
    """Load the storage state at ``path``.

    A missing file yields an empty :class:`StorageState` with ``exists=False``. A file
    that exists but is unreadable or not a JSON object raises
    :class:`StorageStateError` when ``strict`` (the default), so a typo'd
    ``GEMINI_AUTH_STORAGE`` or a half-written file is reported instead of silently
    falling through to "no credentials".

    ``register`` adds the cookie values to the redaction registry. It defaults to
    ``True`` because the moment a secret enters the process is exactly when the
    scrubber needs to know about it; tests that assert on registry contents pass
    ``False``.
    """
    path = path.expanduser()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return StorageState(path=path, document={}, cookies=[], exists=False)
    except OSError as exc:
        if strict:
            raise StorageStateError(f"Cannot read the session file at {path}: {exc}") from exc
        return StorageState(path=path, document={}, cookies=[], exists=False)

    if not raw.strip():
        return StorageState(path=path, document={}, cookies=[], exists=True)

    try:
        document = json.loads(raw)
    except ValueError as exc:
        if strict:
            raise StorageStateError(
                f"The session file at {path} is not valid JSON. "
                "Re-run `gemini-web login` to recreate it."
            ) from exc
        return StorageState(path=path, document={}, cookies=[], exists=True)

    if not isinstance(document, dict):
        if strict:
            raise StorageStateError(
                f"The session file at {path} must contain a JSON object, "
                f"found {type(document).__name__}."
            )
        return StorageState(path=path, document={}, cookies=[], exists=True)

    rows = document.get("cookies")
    cookies = policy.filter_cookies(rows if isinstance(rows, list) else [])
    if register:
        register_secret(*(row["value"] for row in cookies))
    return StorageState(path=path, document=document, cookies=cookies, exists=True)


def merge_cookies(
    document: dict[str, Any],
    incoming: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Return ``document`` with ``incoming`` cookies merged in, and what changed.

    Identity is ``(name, domain-without-dot, path)``. A matching row is replaced in
    place — preserving its position, so a diff of the file stays readable — and a new
    one is appended. Rows we do not own are untouched, which is what makes it safe to
    write NotebookLM's file.

    The returned list names the cookies whose value actually changed, so callers can
    skip the write (and the lock, and the mtime bump) when there is nothing to do.
    """
    merged = dict(document)
    existing = merged.get("cookies")
    rows: list[dict[str, Any]] = list(existing) if isinstance(existing, list) else []

    def identity(row: Any) -> tuple[str, str, str] | None:
        if not isinstance(row, dict):
            return None
        name, domain, path = row.get("name"), row.get("domain"), row.get("path", "/")
        if not isinstance(name, str) or not isinstance(domain, str):
            return None
        return (name, domain.lstrip(".").lower(), path if isinstance(path, str) else "/")

    index = {}
    for position, row in enumerate(rows):
        key = identity(row)
        if key is not None:
            index[key] = position

    changed: list[str] = []
    for row in incoming:
        key = identity(row)
        if key is None:
            continue
        position = index.get(key)
        if position is None:
            rows.append(dict(row))
            index[key] = len(rows) - 1
            changed.append(row["name"])
            continue
        previous = rows[position]
        if isinstance(previous, dict) and previous.get("value") == row.get("value"):
            # Same value: refresh the metadata (expiry moves on rotation) but do not
            # report a change, so an unchanged session does not rewrite the file.
            rows[position] = {**previous, **row}
            continue
        rows[position] = {**previous, **row} if isinstance(previous, dict) else dict(row)
        changed.append(row["name"])

    merged["cookies"] = rows
    merged.setdefault("origins", document.get("origins", []))
    return merged, changed


def save(
    path: Path,
    document: dict[str, Any],
    *,
    lock: bool = True,
) -> None:
    """Write ``document`` to ``path`` atomically, owner-only.

    ``lock=False`` exists only for callers that already hold the sentinel — nesting
    the same exclusive byte-range lock in one process would deadlock on Windows, where
    a second ``msvcrt.locking`` on the same range from another descriptor conflicts.
    """
    path = path.expanduser()
    secure_mkdir(path.parent)
    if lock:
        with file_lock(storage_state_lock_path(path)):
            _write_atomic(path, document)
        return
    _write_atomic(path, document)


def _write_atomic(path: Path, document: dict[str, Any]) -> None:
    """Serialise ``document`` to a sibling temp file, then rename it over ``path``."""
    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        # A failed write must not leave a temp file holding a live credential.
        with contextlib.suppress(OSError):  # already renamed, or never created
            os.unlink(tmp)
        raise
    harden_file(path)


def update_credentials(
    path: Path,
    *,
    psid: str | None = None,
    psidts: str | None = None,
    expires: float | None = None,
    require_matching_psid: bool = True,
) -> list[str]:
    """Merge fresh cookie values into the storage state at ``path``.

    This is the write-back entry point used after a cookie rotation and by the login
    flow. Returns the names that changed — empty when the file was already current, in
    which case nothing was written.

    ``require_matching_psid`` guards the shared-file case: if the storage state belongs
    to a *different* Google session than the one that produced ``psidts``, writing our
    rotated token into it would replace a working credential with one that does not
    match its ``__Secure-1PSID``, logging the other tool out. When the check fails the
    call is a no-op.

    The whole read-modify-write runs inside the sentinel lock, so a concurrent writer
    cannot land between our read and our write.
    """
    if not psid and not psidts:
        return []

    path = path.expanduser()
    secure_mkdir(path.parent)
    with file_lock(storage_state_lock_path(path)):
        state = load(path, strict=False)
        current_psid = state.psid
        if require_matching_psid and current_psid and psid and current_psid != psid:
            return []

        rows: list[dict[str, Any]] = []
        for name, value in ((policy.PSID, psid), (policy.PSIDTS, psidts)):
            if not value:
                continue
            row: dict[str, Any] = {
                "name": name,
                "value": value,
                "domain": ".google.com",
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "None",
            }
            if expires is not None:
                row["expires"] = float(expires)
            rows.append(policy.sanitize_row({**row, "expires": row.get("expires", -1.0)}))

        document, changed = merge_cookies(state.document or {"cookies": [], "origins": []}, rows)
        if not changed:
            return []
        register_secret(*(row["value"] for row in rows))
        save(path, document, lock=False)
        return changed


def clear_credentials(path: Path) -> list[str]:
    """Remove this package's cookies from the storage state, leaving the rest intact.

    Used by ``gemini-web logout --shared``. Removing only our two names means a shared file
    keeps whatever another tool put there; the Google session itself is of course still
    valid until the server expires it, which the CLI's output says out loud.
    """
    path = path.expanduser()
    if not path.exists():
        return []
    with file_lock(storage_state_lock_path(path)):
        state = load(path, strict=False)
        rows = state.document.get("cookies")
        if not isinstance(rows, list):
            return []
        kept, removed = [], []
        for row in rows:
            name = row.get("name") if isinstance(row, dict) else None
            if isinstance(name, str) and name in policy.ALLOWED_COOKIE_NAMES:
                removed.append(name)
                continue
            kept.append(row)
        if not removed:
            return []
        document = dict(state.document)
        document["cookies"] = kept
        save(path, document, lock=False)
        return removed
