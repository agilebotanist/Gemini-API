import sys

from loguru import logger as _logger

_handler_id = None


def set_log_level(level: str | int) -> None:
    """Set the log level for gemini_webapi. The default log level is "INFO".

    Note: calling this function for the first time will globally remove all existing loguru
    handlers. To avoid this, you may want to set logging behaviors directly with loguru.

    Parameters
    ----------
    level : `str | int`
        Log level: "TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"

    Examples
    --------
    >>> from gemini_webapi import set_log_level
    >>> set_log_level("DEBUG")  # Show debug messages
    >>> set_log_level("ERROR")  # Only show errors

    """
    global _handler_id

    _logger.remove(_handler_id)

    _handler_id = _logger.add(
        sys.stderr,
        level=level,
        filter=lambda record: record["extra"].get("name") == "gemini_webapi",
    )


def _scrub(record) -> None:
    """Remove credential values from every record this package emits.

    Attached once, here, at import time rather than registered later: the whole point
    is that scrubbing is not something a call site can forget. The import is local
    because :mod:`gemini_webapi.auth.redaction` is a leaf module and this one is
    imported by everything, so a module-level import would close the cycle.
    """
    from gemini_webapi.auth.redaction import scrub_record

    scrub_record(record)


# `patch` is applied to the *bound* logger, so only gemini_webapi's own records pass
# through the scrubber. A library must not reconfigure the host application's logging.
logger = _logger.bind(name="gemini_webapi").patch(_scrub)
