"""``gemini-web login`` / ``logout`` / ``auth status`` / ``doctor``.

These four are the session commands; every other command consumes what they produce.
They are the only place in the CLI that talks to :mod:`gemini_webapi.auth` directly,
and they are synchronous — a browser login is not something to interleave with an
event loop that also streams model output.

Output discipline: these commands print paths, counts, timestamps and fingerprints.
There is no code path here that formats a cookie value, and
``tests/unit/test_no_secret_leak.py`` asserts it by feeding a known value through the
whole surface and grepping the captured output.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import playwright_login, resolver, storage_state
from gemini_webapi.auth.playwright_login import LoginError, LoginPlan
from gemini_webapi.auth.redaction import fingerprint
from gemini_webapi.utils import set_log_level

#: Exit codes. 0 success, 1 a real failure, 2 "nothing is wrong but there is no
#: session" — the state a wrapper script wants to distinguish so it can trigger a
#: login instead of reporting an error.
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_NO_SESSION = 2
#: A capture was refused rather than written - a different session than the stored one,
#: or one that failed verification (ADR-0009). The stored session is untouched, which is
#: a different situation from "login failed and you have nothing".
EXIT_NOT_REPLACED = 3


def _emit(message: str) -> None:
    print(message)


def cmd_login(args) -> int:
    """Sign in with a real browser, or refresh an existing session headlessly."""
    try:
        plan = LoginPlan.build(
            profile=getattr(args, "profile", None),
            headless=bool(args.headless),
            timeout=args.timeout,
            channel=args.channel,
            allow_shared=not getattr(args, "no_shared", False),
            browser_profile_dir=Path(args.browser_profile) if args.browser_profile else None,
            allow_switch=bool(args.switch_account),
            verify=not args.no_verify,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL

    print(
        f"Session file:    {plan.storage_path}{'  (shared with notebooklm)' if plan.shared else ''}"
    )
    print(f"Browser profile: {plan.browser_profile_dir}")
    if not plan.headless:
        print("A Chromium window will open. Sign in to your Google account there.")

    try:
        result = playwright_login.run_login(plan, emit=_emit)
    except LoginError as exc:
        print(f"\n{exc}", file=sys.stderr)
        return EXIT_FAIL

    if not result.ok:
        print(f"\n{result.message}", file=sys.stderr)
        if result.status == playwright_login.STATUS_NO_SESSION:
            return EXIT_NO_SESSION
        if result.status in {playwright_login.STATUS_MISMATCH, playwright_login.STATUS_UNVERIFIED}:
            # A distinct code, because "the stored session is untouched and probably
            # still fine" is a different situation for a wrapper script than "login
            # failed and you have nothing".
            return EXIT_NOT_REPLACED
        return EXIT_FAIL

    if result.switched_account:
        print(
            f"\nReplaced the stored session {result.previous_psid} with {result.psid}"
            f"{f' (verified {result.verify_status})' if result.verified else ''}. "
            "Any tool sharing this file now uses this session."
        )

    verb = "Captured" if result.status == playwright_login.STATUS_CAPTURED else "Confirmed"
    print(f"\n{verb} the Gemini session.")
    print(f"  cookies:  {', '.join(result.cookie_names) or '(none)'}")
    print(f"  psid:     {result.psid}")
    print(f"  psidts:   {result.psidts}")
    print(
        f"  written:  {', '.join(result.changed) if result.changed else 'nothing (already current)'}"
    )
    print(f"  file:     {result.storage_path}")

    removed = playwright_login.purge_legacy_cache(resolver._legacy_cache_files())
    if removed:
        print(f"  cleaned:  {len(removed)} legacy cache file(s) whose names embedded a session id")
    return EXIT_OK


def cmd_logout(args) -> int:
    """Drop the local session material this package wrote.

    Deliberately conservative about the shared file. Removing the cookies from
    NotebookLM's storage state logs *that* tool out too, which is rarely what someone
    typing ``gemini-web logout`` means, so it takes ``--shared`` to say it explicitly. The
    Google session itself keeps living on Google's side either way — this is a local
    credential deletion, not a sign-out, and the output says so.
    """
    target = auth_paths.storage_target(
        getattr(args, "profile", None),
        allow_shared=not getattr(args, "no_shared", False),
    )
    removed_any = False

    cache_dir = auth_paths.cookie_cache_dir()
    cached = sorted(cache_dir.glob(".cached_cookies_*.json")) if cache_dir.is_dir() else []
    for path in cached:
        try:
            path.unlink()
            removed_any = True
        except OSError as exc:
            print(f"warning: could not remove {path}: {exc}", file=sys.stderr)
    if cached:
        print(f"Removed {len(cached)} cached cookie file(s) from {cache_dir}")

    legacy = resolver._legacy_cache_files()
    if legacy:
        names = playwright_login.purge_legacy_cache(legacy)
        removed_any = removed_any or bool(names)
        print(
            f"Removed {len(names)} legacy cache file(s) from {auth_paths.legacy_cookie_cache_dir()}"
        )

    if target.shared and not args.shared:
        print(
            f"Left the shared session file untouched: {target.path}\n"
            "  It is notebooklm's too. Pass --shared to strip Gemini's cookies from it."
        )
    elif target.path.exists():
        if target.shared:
            names = storage_state.clear_credentials(target.path)
            removed_any = removed_any or bool(names)
            print(f"Removed {', '.join(names) or 'nothing'} from {target.path}")
        else:
            try:
                target.path.unlink()
                removed_any = True
                print(f"Removed {target.path}")
            except OSError as exc:
                print(f"error: could not remove {target.path}: {exc}", file=sys.stderr)
                return EXIT_FAIL

    if args.browser_profile and target.browser_profile_dir.is_dir():
        print(
            f"Browser profile kept: {target.browser_profile_dir}\n"
            "  Delete it by hand to force a full interactive login next time."
        )

    if not removed_any:
        print("Nothing to remove.")
    print("\nNote: this only deleted local credentials. The Google session itself is still")
    print("valid - sign out at https://myaccount.google.com/ to end it server-side.")
    return EXIT_OK


def cmd_auth_status(args) -> int:
    """Report where the session comes from, and whether it is usable."""
    report = resolver.status(
        getattr(args, "profile", None),
        allow_shared=None if not getattr(args, "no_shared", False) else False,
    )
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK if report.get("resolved") else EXIT_NO_SESSION

    storage: dict[str, Any] = report["storage"]  # type: ignore[assignment]
    print("=== Gemini session ===\n")
    print(f"  profile:          {report['profile']}")
    print(f"  session file:     {storage.get('path')}")
    print(
        f"  source:           {report['storage_source']}"
        f"{'  (shared with notebooklm)' if report['storage_shared'] else ''}"
    )
    print(f"  file exists:      {_yesno(storage.get('exists'))}")
    if report.get("storage_error"):
        print(f"  file problem:     {report['storage_error']}")
    print(
        f"  cookies in file:  {storage.get('usable_cookies')} usable / {storage.get('total_cookies')} total"
    )
    print(
        f"  __Secure-1PSID:   {storage.get('psid')}  expires {storage.get('psid_expires') or '-'}"
    )
    print(
        f"  __Secure-1PSIDTS: {storage.get('psidts')}  expires {storage.get('psidts_expires') or '-'}"
    )
    if storage.get("foreign_keys"):
        print(f"  other tools' keys: {', '.join(storage['foreign_keys'])} (preserved on write)")
    print(f"  last modified:    {storage.get('modified') or '-'}")

    resolved = report.get("resolved")
    print("\n  resolved from:    " + (resolved["source"] if resolved else "NOTHING - no session"))
    print(
        f"  browser profile:  {report['browser_profile']} "
        f"({'present' if report['browser_profile_exists'] else 'absent'})"
    )
    print(
        f"  sharing:          {_onoff(report['sharing_enabled'])}"
        f"   write-back: {_onoff(report['writeback_enabled'])}"
    )
    print(f"  playwright:       {report['playwright']}")
    print(f"  cookie cache:     {report['cookie_cache_dir']}")
    if report["legacy_cache_files"]:
        print(
            f"  ⚠ legacy cache:   {len(report['legacy_cache_files'])} file(s) in "
            f"{auth_paths.legacy_cookie_cache_dir()} - names embed a session id, "
            "run `gemini-web auth purge`"
        )
    if report["env_credentials"]:
        print("  ⚠ env cookies:    GEMINI_SECURE_1PSID is set and takes precedence over the file")

    if not resolved:
        print("\n  No session. Run `gemini-web login`.")
        return EXIT_NO_SESSION
    return EXIT_OK


def cmd_auth_purge(args) -> int:
    """Delete the pre-fork cache files whose names leaked the session id."""
    legacy = resolver._legacy_cache_files()
    if not legacy:
        print(f"No legacy cache files in {auth_paths.legacy_cookie_cache_dir()}.")
        return EXIT_OK
    removed = playwright_login.purge_legacy_cache(legacy)
    print(f"Removed {len(removed)} file(s) from {auth_paths.legacy_cookie_cache_dir()}:")
    for name in removed:
        print(f"  {name}")
    if len(removed) != len(legacy):
        print("Some files could not be removed; check permissions.", file=sys.stderr)
        return EXIT_FAIL
    return EXIT_OK


def cmd_doctor(args) -> int:
    """Check the things that actually break, and say what to do about each."""
    report = resolver.status(getattr(args, "profile", None))
    storage: dict[str, Any] = report["storage"]  # type: ignore[assignment]
    problems: list[str] = []
    warnings: list[str] = []

    print("=== gemini-web doctor ===\n")

    available = report["playwright_available"]
    _line("playwright", available, report["playwright"])
    if not available:
        problems.append(
            'Install the login dependency: pip install "gemini-webapi[playwright]" '
            "&& python -m playwright install chromium"
        )

    _line("session file", bool(storage.get("exists")), str(storage.get("path")))
    if not storage.get("exists"):
        problems.append("No session file. Run `gemini-web login`.")
    if report.get("storage_error"):
        problems.append(f"Session file unreadable: {report['storage_error']}")

    has_psid = storage.get("psid") not in (None, "-")
    _line("__Secure-1PSID", has_psid, str(storage.get("psid")))
    if storage.get("exists") and not has_psid:
        problems.append("The session file has no Gemini cookies. Run `gemini-web login`.")

    _line(
        "__Secure-1PSIDTS",
        storage.get("psidts") not in (None, "-"),
        f"{storage.get('psidts')} (optional for some accounts)",
    )

    _line(
        "browser profile",
        bool(report["browser_profile_exists"]),
        f"{report['browser_profile']} "
        f"({'headless refresh possible' if report['browser_profile_exists'] else 'interactive login needed'})",
    )

    _line("write-back", bool(report["writeback_enabled"]), _onoff(report["writeback_enabled"]))
    if report["storage_shared"] and not report["writeback_enabled"]:
        warnings.append(
            "Sharing notebooklm's session file with write-back disabled: a cookie "
            "rotation here will invalidate notebooklm's copy. Unset GEMINI_AUTH_WRITEBACK."
        )

    world_readable = bool(storage.get("world_readable"))
    _line(
        "file permissions",
        not world_readable,
        "owner-only" if not world_readable else "GROUP/WORLD READABLE",
    )
    if world_readable:
        problems.append(f"chmod 600 {storage.get('path')} - it holds a live session cookie.")

    legacy = report["legacy_cache_files"]
    _line(
        "legacy cache",
        not legacy,
        "clean" if not legacy else f"{len(legacy)} file(s) name a session id",
    )
    if legacy:
        problems.append("Run `gemini-web auth purge` to delete pre-fork cache files.")

    if report["env_credentials"]:
        warnings.append(
            "GEMINI_SECURE_1PSID is set in the environment and overrides the session "
            "file. Environment variables leak into child processes and crash reports."
        )

    _line(
        "resolved session",
        bool(report["resolved"]),
        report["resolved"]["source"] if report["resolved"] else "none",
    )

    # Everything above is a file check. Whether Google still honours the session is not
    # knowable offline - a session file can be perfect and the session dead (revoked,
    # expired, or superseded), which is exactly the state that sends people to `doctor`.
    if getattr(args, "live", False) and report["resolved"]:
        from gemini_webapi.auth import resolver as _resolver
        from gemini_webapi.auth.verify import verify_credentials

        credentials = _resolver.resolve(profile=getattr(args, "profile", None))
        probe = verify_credentials(credentials.psid, credentials.psidts)
        _line(
            "live session",
            probe.ok is not False,
            f"{probe.status} - {probe.detail}",
        )
        if probe.ok is False:
            problems.append(
                "Google does not accept the stored session any more. Restore it with one "
                "login:\n"
                "      notebooklm login --browser-cookies chrome --account EMAIL  "
                "(Chrome fully closed)\n"
                "      gemini-web login --switch-account                          "
                "(browser window)\n"
                "    A session imported from a running browser goes stale quickly - the "
                "browser keeps rotating the same credential. For a durable one, mint a "
                "master token: `notebooklm login --master-token --account EMAIL`."
            )
        elif probe.unknown:
            warnings.append(f"Could not reach Gemini to check the session live: {probe.detail}")

    if warnings:
        print("\nWarnings:")
        for item in warnings:
            print(f"  ! {item}")
    if problems:
        print("\nTo fix:")
        for item in problems:
            print(f"  - {item}")
        return EXIT_FAIL
    print("\nAll checks passed.")
    return EXIT_OK


def _line(label: str, ok: bool, detail: str) -> None:
    print(f"  [{'ok' if ok else '!!'}] {label:<18} {detail}")


def _yesno(value: Any) -> str:
    return "yes" if value else "no"


def _onoff(value: Any) -> str:
    return "enabled" if value else "disabled"


def register_parsers(sub) -> None:
    """Attach the session commands to the CLI's subparser collection.

    Kept next to the implementations so a new flag is one edit, not two files.
    """
    p_login = sub.add_parser(
        "login",
        help="Sign in with a browser and store the session (or refresh it with --headless)",
    )
    p_login.add_argument(
        "--headless",
        action="store_true",
        help="Refresh the session from the existing browser profile without a window. "
        "Requires a previous interactive login.",
    )
    p_login.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Seconds to wait for the sign-in (default 300 interactive, 45 headless)",
    )
    p_login.add_argument(
        "--channel",
        default=None,
        help="Chromium channel to launch, e.g. 'chrome' to use the installed Google Chrome",
    )
    p_login.add_argument(
        "--browser-profile",
        default=None,
        help="Override the persistent browser profile directory",
    )
    p_login.add_argument(
        "--switch-account",
        action="store_true",
        help="Allow the capture to replace a *different* stored session. Needed when "
        "signing in as another Google account, and refused by default because a browser "
        "profile can also hold a stale cookie that would overwrite a working session.",
    )
    p_login.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the live check that a session-changing capture actually authenticates. "
        "Only with --switch-account, and only if you know what the capture is.",
    )

    p_logout = sub.add_parser("logout", help="Delete the locally stored session material")
    p_logout.add_argument(
        "--shared",
        action="store_true",
        help="Also strip Gemini's cookies from a session file shared with notebooklm",
    )
    p_logout.add_argument(
        "--browser-profile",
        action="store_true",
        help="Report the browser profile directory (never deleted automatically)",
    )

    p_auth = sub.add_parser("auth", help="Inspect and maintain the stored session")
    auth_sub = p_auth.add_subparsers(dest="auth_command")
    p_status = auth_sub.add_parser("status", help="Where the session comes from and its state")
    p_status.add_argument("--json", action="store_true", help="Machine-readable output")
    auth_sub.add_parser("purge", help="Delete pre-fork cache files that name a session id")

    p_doctor = sub.add_parser(
        "doctor", help="Check the auth setup and say how to fix what is broken"
    )
    p_doctor.add_argument(
        "--live",
        action="store_true",
        help="Also ask Gemini whether the stored session still works (one request). "
        "The file checks cannot tell a valid session from a revoked one.",
    )


def dispatch(args) -> int | None:
    """Run the session command in ``args``, or return ``None`` if it is not ours."""
    command = args.command
    if command in {"login", "logout", "auth", "doctor"}:
        # These commands *are* the report. The library's own INFO/WARNING lines - which
        # loguru prints to stderr through its default handler until someone configures
        # it - would otherwise interleave a stack of "Account status: ..." warnings with
        # the table that says the same thing more usefully. `--verbose` restores them.
        set_log_level("DEBUG" if getattr(args, "verbose", False) else "ERROR")
    if command == "login":
        return cmd_login(args)
    if command == "logout":
        return cmd_logout(args)
    if command == "doctor":
        return cmd_doctor(args)
    if command == "auth":
        auth_command = getattr(args, "auth_command", None)
        if auth_command == "status":
            return cmd_auth_status(args)
        if auth_command == "purge":
            return cmd_auth_purge(args)
        print("Usage: gemini-web auth {status|purge}", file=sys.stderr)
        return EXIT_FAIL
    return None


def environment_summary() -> dict[str, str]:
    """Return the auth-relevant environment variables that are set, values elided.

    Used by ``doctor``'s verbose mode and by bug reports: knowing that
    ``GEMINI_AUTH_STORAGE`` is set is the whole diagnosis half the time, and its value
    is a path rather than a secret — but ``GEMINI_SECURE_1PSID`` is a secret, so
    presence is all this reports for the cookie variables.
    """
    result = {}
    for name in (
        auth_paths.GEMINI_HOME_ENV,
        auth_paths.GEMINI_AUTH_STORAGE_ENV,
        auth_paths.GEMINI_AUTH_PROFILE_ENV,
        auth_paths.GEMINI_AUTH_SHARED_ENV,
        auth_paths.GEMINI_AUTH_WRITEBACK_ENV,
        auth_paths.GEMINI_COOKIE_PATH_ENV,
        auth_paths.NOTEBOOKLM_HOME_ENV,
    ):
        if (value := os.environ.get(name)) is not None:
            result[name] = value
    for name in (auth_paths.GEMINI_SECURE_1PSID_ENV, auth_paths.GEMINI_SECURE_1PSIDTS_ENV):
        if (value := os.environ.get(name)) is not None:
            result[name] = fingerprint(value)
    return result
