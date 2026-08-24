import time
from pathlib import Path

import orjson as json
from curl_cffi.requests import AsyncSession, Cookies

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import writeback
from gemini_webapi.auth.redaction import fingerprint, register_secret
from gemini_webapi.constants import Endpoint, Headers, format_http_version
from gemini_webapi.exceptions import AuthError

from .logger import logger


def _extract_cookie_value(cookies: Cookies, name: str) -> str | None:
    """Extract a cookie value from a curl_cffi Cookies jar."""
    return next((cookie.value for cookie in cookies.jar if cookie.name == name), None)


def _get_cookie_cache_dir() -> Path:
    """Lazy helper to get the cookie cache directory.

    Delegates to :func:`gemini_webapi.auth.paths.cookie_cache_dir`, which moved the
    default out of the shared temp directory. ``GEMINI_COOKIE_PATH`` still overrides.
    """
    return auth_paths.cookie_cache_dir()


def _get_cookies_cache_path(cookies: Cookies, verbose: bool = False) -> Path | None:
    """Helper to get the cache file path for the session in ``cookies``.

    The filename carries a truncated SHA-256 of ``__Secure-1PSID``, not the value
    itself. Before the fork it was the raw cookie, in a world-readable temp directory:
    a directory listing handed over a working Google session, and no file permission
    could fix that because the leak was the *name* (ADR-0005). Old files are found and
    removed by ``gemini-web auth purge``.
    """
    secure_1psid = _extract_cookie_value(cookies, "__Secure-1PSID")
    if not secure_1psid:
        if verbose:
            logger.warning("Cannot save cookies: __Secure-1PSID not found.")
        return None

    return auth_paths.cookie_cache_path(secure_1psid)


async def rotate_1psidts(client: AsyncSession, verbose: bool = False) -> str | None:
    """Refresh the __Secure-1PSIDTS cookie and store the refreshed cookie value in cache file.

    Parameters
    ----------
    client : `curl_cffi.requests.AsyncSession`
        The shared async session to use for the request.
    verbose: `bool`, optional
        If `True`, will print more infomation in logs.

    Returns
    -------
    `str | None`
        New value of the __Secure-1PSIDTS cookie if rotation was successful.

    Raises
    ------
    `gemini_webapi.AuthError`
        If request failed with 401 Unauthorized.
    `curl_cffi.requests.exceptions.HTTPError`
        If request failed with other status codes.

    """
    path = _get_cookies_cache_path(client.cookies, verbose)
    if not path:
        return None

    # Check if the cache file was modified in the last minute to avoid 429 Too Many Requests
    if path.is_file() and time.time() - path.stat().st_mtime <= 60:
        if verbose:
            logger.debug("Rotation skipped, cache is still fresh (< 60s).")
        return _extract_cookie_value(client.cookies, "__Secure-1PSIDTS")

    response = await client.post(
        url=Endpoint.ROTATE_COOKIES,
        headers=Headers.ROTATE_COOKIES.value,
        data='[000,"-0000000000000000000"]',
    )
    if verbose:
        logger.debug(
            f"HTTP Request: POST {Endpoint.ROTATE_COOKIES} [{response.status_code}] (HTTP/{format_http_version(response.http_version)})"
        )
    if response.status_code == 401:
        raise AuthError
    response.raise_for_status()

    save_cookies(client.cookies, verbose)
    if new_1psidts := _extract_cookie_value(client.cookies, "__Secure-1PSIDTS"):
        if verbose:
            logger.debug(f"Rotated __Secure-1PSIDTS ({fingerprint(new_1psidts)}).")
        return new_1psidts

    cookie_names = [c.name for c in client.cookies.jar]
    logger.debug(
        f"Rotation completed but __Secure-1PSIDTS not found. Response cookies: {cookie_names}"
    )
    return None


def clear_cookies_cache(cookies: Cookies, verbose: bool = False) -> None:
    """Delete the cached cookies for a session.

    Cached cookies are tried before the ones the caller supplied, and are accepted as soon
    as they yield an access token - which an unauthenticated session also does. Stale cache
    entries would therefore keep shadowing valid credentials indefinitely, so a session that
    turns out to be unauthenticated drops its cache instead of preserving it.

    Parameters
    ----------
    cookies: `curl_cffi.requests.Cookies`
        Cookies identifying the cache entry, by their `__Secure-1PSID`.
    verbose: `bool`, optional
        If `True`, will print more infomation in logs.

    """
    path = _get_cookies_cache_path(cookies, verbose)
    if not path or not path.is_file():
        return

    try:
        path.unlink()
        logger.debug(f"Cleared cached cookies at {path}.")
    except OSError as e:
        if verbose:
            logger.warning(f"Failed to clear cached cookies at {path}: {e}")


def save_cookies(cookies: Cookies, verbose: bool = False) -> None:
    """Save persistent cookies to the cache file, and back to the shared session file.

    Two destinations, one call site, because both must happen on exactly the same
    events (a rotation, and a client shutdown):

    * the **cache**, which is this package's fast path on the next start;
    * the **storage state**, which may be shared with ``notebooklm``. A rotation
      invalidates the previous ``__Secure-1PSIDTS``, so keeping the new one to
      ourselves would log the other tool out of a session the user established once
      (ADR-0006). Disable with ``GEMINI_AUTH_WRITEBACK=0``.

    The write-back is best-effort: it never raises into the rotation path, which runs
    in a background task whose failure the user cannot see.
    """
    path = _get_cookies_cache_path(cookies, verbose)
    if not path:
        return

    _writeback_to_storage_state(cookies, verbose)

    cookie_list = []
    for cookie in cookies.jar:
        is_auth_cookie = cookie.name in ["__Secure-1PSID", "__Secure-1PSIDTS"]
        domain = cookie.domain.lstrip(".").lower() if cookie.domain else ""
        is_google_domain = domain == "google.com" or domain.endswith(".google.com")
        if is_google_domain and (
            is_auth_cookie or (cookie.expires is not None and not cookie.is_expired())
        ):
            cookie_list.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "expires": cookie.expires,
                }
            )

    if cookie_list:
        # The directory is created owner-only, not just the file: on the previous
        # default (a shared temp dir) the enclosing directory was world-listable, and
        # a 0600 file inside a 0777 directory still leaks who has a session and when.
        auth_paths.secure_mkdir(path.parent)
        path.write_text(json.dumps(cookie_list).decode("utf-8"))
        auth_paths.harden_file(path)  # owner read/write only
        if verbose:
            logger.debug(f"Saved cookies to cache successfully ({len(cookie_list)} cookies).")


def _writeback_to_storage_state(cookies: Cookies, verbose: bool = False) -> None:
    """Mirror the current Gemini cookies into the (possibly shared) storage state."""
    psid = _extract_cookie_value(cookies, "__Secure-1PSID")
    psidts = _extract_cookie_value(cookies, "__Secure-1PSIDTS")
    register_secret(psid, psidts)
    try:
        changed = writeback.sync_from_jar(cookies.jar)
    except Exception as e:  # pragma: no cover - defensive: rotation must not fail here
        if verbose:
            logger.debug(f"Storage-state write-back skipped: {type(e).__name__}.")
        return
    if verbose and changed:
        logger.debug(writeback.describe(changed, psidts))
