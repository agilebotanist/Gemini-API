"""Secret fingerprinting and log/output scrubbing.

The auth layer's rule is that a cookie **value** never reaches a human-visible
surface: no log line, no exception message, no ``--verbose`` dump, no CLI table, no
``repr()``. Two mechanisms enforce it, and both live here so there is one thing to
review:

**Fingerprints.** Anything that wants to *identify* a credential prints
:func:`fingerprint` — a truncated SHA-256 of the value, e.g. ``sha256:1f3a9c02``.
That is enough to answer the questions people actually ask ("is this the same
session the other tool has?", "did the cookie change after rotation?") and useless
to an attacker who reads it.

**Scrubbing.** Values that were never meant to be printed still escape through
third-party tracebacks and subprocess output. :func:`register_secret` adds a value to
a process-wide registry and :func:`scrub` removes every registered value — plus
anything shaped like a Google session cookie — from a string. :func:`scrub_record` is
attached to the package's loguru logger at definition time, so scrubbing is the default
for gemini-webapi's own logging rather than something each call site remembers.

Scrubbing is defence in depth, not the primary control. The primary control is that
this package's own code passes fingerprints, never values. Tests in
``tests/unit/test_no_secret_leak.py`` assert both halves.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

#: Prefix that marks a fingerprint, so a reader can tell it apart from a real value.
FINGERPRINT_PREFIX = "sha256:"
#: Hex characters kept from the digest. 8 gives ~4 billion buckets: plenty to compare
#: two credentials for equality, far too few to attack the pre-image of a 200+ char
#: cookie, and short enough to fit in a table column.
FINGERPRINT_CHARS = 8
#: What a scrubbed value is replaced with, carrying the fingerprint so the redacted
#: line stays diagnostically useful.
REDACTED_TEMPLATE = "<redacted:{fingerprint}>"

#: Values shorter than this are never registered as secrets: substring-replacing a
#: 3-character string would corrupt unrelated output with no security benefit.
MIN_SECRET_LEN = 12

#: Cookie names whose values are session-bearing. Used to scrub ``name=value`` and
#: ``"name": "value"`` shapes even when the value was never registered — a traceback
#: from a dependency can carry a cookie we have not seen.
SENSITIVE_COOKIE_NAMES = frozenset(
    {
        "__Secure-1PSID",
        "__Secure-1PSIDTS",
        "__Secure-1PSIDCC",
        "__Secure-1PSIDRTS",
        "__Secure-3PSID",
        "__Secure-3PSIDTS",
        "__Secure-3PSIDCC",
        "__Secure-3PSIDRTS",
        "__Secure-1PAPISID",
        "__Secure-3PAPISID",
        "__Secure-OSID",
        "__Host-1PLSID",
        "__Host-3PLSID",
        "__Host-GAPS",
        "__Host-GAPSTS",
        "SID",
        "HSID",
        "SSID",
        "APISID",
        "SAPISID",
        "SIDCC",
        "LSID",
        "OSID",
        "NID",
    }
)

_NAME_ALTERNATION = "|".join(
    sorted((re.escape(n) for n in SENSITIVE_COOKIE_NAMES), key=len, reverse=True)
)
# `NAME=value` (cookie header / query string shape). The value runs to the next
# delimiter that cannot appear inside a cookie value.
_ASSIGNMENT_RE = re.compile(rf"\b({_NAME_ALTERNATION})=([^;,\s\"']+)")
# `"NAME": "value"` / `'NAME': 'value'` (JSON shape, e.g. a storage_state fragment).
_JSON_PAIR_RE = re.compile(rf"([\"']({_NAME_ALTERNATION})[\"']\s*:\s*)[\"']([^\"']+)[\"']")
# `"value": "g.a000..."` — a storage_state cookie row prints the name and the value as
# two separate keys, so the pair form above cannot see the association. Google session
# cookie values are recognisable on their own: the `g.a0` family is what Gemini and
# NotebookLM issue today, and the length floor keeps ordinary strings out.
_GOOGLE_TOKEN_RE = re.compile(r"\bg\.a0[A-Za-z0-9_\-]{24,}")

_registry: set[str] = set()
_registry_lock = threading.Lock()


def fingerprint(value: str | bytes | None) -> str:
    """Return a short, stable, non-reversible identifier for ``value``.

    ``None`` and the empty string both yield ``"-"``: absence is a normal state for
    ``__Secure-1PSIDTS`` (some accounts have none) and must be distinguishable from a
    value at a glance, without a fingerprint that looks like a real one.
    """
    if not value:
        return "-"
    raw = value.encode("utf-8") if isinstance(value, str) else value
    digest = hashlib.sha256(raw).hexdigest()[:FINGERPRINT_CHARS]
    return f"{FINGERPRINT_PREFIX}{digest}"


def register_secret(*values: str | None) -> None:
    """Add ``values`` to the process-wide scrubbing registry.

    Call this wherever a credential enters the process — reading a storage state,
    parsing a cookie file, capturing from a browser. Registration is additive and
    process-wide because the leak we are guarding against (a dependency's traceback)
    happens far away from the code that read the value.

    Values shorter than :data:`MIN_SECRET_LEN` are ignored; see the constant.
    """
    fresh = {v for v in values if isinstance(v, str) and len(v) >= MIN_SECRET_LEN}
    if not fresh:
        return
    with _registry_lock:
        _registry.update(fresh)


def registered_secret_count() -> int:
    """Return how many values the registry holds (for diagnostics and tests)."""
    with _registry_lock:
        return len(_registry)


def clear_registry() -> None:
    """Forget every registered secret. Intended for tests and long-lived servers."""
    with _registry_lock:
        _registry.clear()


def scrub(text: Any) -> str:
    """Return ``text`` with every known or cookie-shaped secret replaced.

    Order matters: registered exact values are replaced first (they are the ones we
    are certain about), then the structural patterns catch values this process never
    held. Each replacement keeps the fingerprint, so two redactions of the same value
    are still comparable in a log.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text

    with _registry_lock:
        # Longest first: a secret that contains another (PSIDTS values embed
        # timestamps that can repeat) must be replaced as a whole.
        secrets = sorted(_registry, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED_TEMPLATE.format(fingerprint=fingerprint(secret)))

    text = _ASSIGNMENT_RE.sub(
        lambda m: f"{m.group(1)}={REDACTED_TEMPLATE.format(fingerprint=fingerprint(m.group(2)))}",
        text,
    )
    text = _JSON_PAIR_RE.sub(
        lambda m: f'{m.group(1)}"{REDACTED_TEMPLATE.format(fingerprint=fingerprint(m.group(3)))}"',
        text,
    )
    return _GOOGLE_TOKEN_RE.sub(
        lambda m: REDACTED_TEMPLATE.format(fingerprint=fingerprint(m.group(0))),
        text,
    )


def cookie_summary(cookies: Iterable[Mapping[str, Any]]) -> str:
    """Return a value-free one-line summary of cookie rows.

    The shape the auth layer logs instead of a cookie list: names, domains and
    fingerprints. Useful for "which cookies did the browser hand us?" and unusable as
    a credential.
    """
    parts = []
    for cookie in cookies:
        name = cookie.get("name")
        if not isinstance(name, str):
            continue
        domain = cookie.get("domain", "?")
        value = cookie.get("value")
        parts.append(f"{name}@{domain}={fingerprint(value if isinstance(value, str) else None)}")
    return ", ".join(parts) if parts else "(none)"


def scrub_record(record: Any) -> None:
    """loguru patcher that scrubs a record's message in place.

    Installed once, at definition time, on the package's bound logger in
    :mod:`gemini_webapi.utils.logger` — not registered at runtime and not applied to
    the root loguru logger. A library that reconfigured the host application's
    logging would be overstepping; patching only the logger this package emits
    through gets every ``gemini_webapi`` line scrubbed and leaves the application's
    own sinks alone.

    ``record`` is loguru's record ``dict``; the message is what every sink formats,
    so rewriting it here is what makes scrubbing unconditional rather than something
    each ``logger.debug`` call has to remember.
    """
    # A patcher that raises would break logging itself, so failure is swallowed.
    with contextlib.suppress(Exception):
        record["message"] = scrub(record["message"])
