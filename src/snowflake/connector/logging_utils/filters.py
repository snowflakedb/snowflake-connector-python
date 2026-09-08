from __future__ import annotations

import logging
import os
from collections.abc import Iterable

from snowflake.connector.secret_detector import SecretDetector

# Set to "true" to leave connector logs unmasked. Honored at emit time, so it
# remains an escape hatch after import (e.g. a log pipeline that depends on
# record.args remaining uninterpolated). Set before import to also skip
# installing the getLogger hook. SNOW-3675583.
DISABLE_LOG_SECRET_MASKING_ENV = "SNOWFLAKE_DISABLE_LOG_SECRET_MASKING"

_MASKING_FAILED_MSG = "<log message masking failed>"

_original_manager_getLogger = None
_hooked_prefixes: tuple[str, ...] = ()


def _log_secret_masking_disabled() -> bool:
    # Case-insensitive "true" only.
    return os.environ.get(DISABLE_LOG_SECRET_MASKING_ENV, "").lower() == "true"


def _name_matches_prefix(name: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if name == prefix or name.startswith(prefix + "."):
            return True
    return False


def add_filter_to_logger_and_children(
    base_logger_name: str, filter_instance: logging.Filter
) -> None:
    # Ensure the base logger exists and apply filter
    base_logger = logging.getLogger(base_logger_name)
    if filter_instance not in base_logger.filters:
        base_logger.addFilter(filter_instance)

    all_loggers_pairs = logging.root.manager.loggerDict.items()
    for name, obj in all_loggers_pairs:
        if not name.startswith(base_logger_name + "."):
            continue

        if not isinstance(obj, logging.Logger):
            continue  # Skip placeholders

        if filter_instance not in obj.filters:
            obj.addFilter(filter_instance)


class SecretMaskingFilter(logging.Filter):
    """
    A logging filter that masks sensitive information in log messages using the SecretDetector utility.

    This filter is designed for scenarios where you want to avoid applying SecretDetector globally
    as a formatter on all logging handlers. Global masking can introduce unnecessary computational
    overhead, particularly for internal logs where secrets are already handled explicitly.
    It would be also easy to bypass unintentionally by simply adding a neighbouring handler to a logger
    - without SecretDetector set as a formatter.

    On the other hand, libraries or submodules often do not have any handler attached, so formatting can't be
    configured on those level, while attaching new handler for that can cause unintended log output or its duplication.

    The connector attaches this filter to named logger trees (not to every handler
    in the process). See ``install_secret_masking_filters``. Opt out with
    ``SNOWFLAKE_DISABLE_LOG_SECRET_MASKING=true``.

    ⚠ Important:
        - Logging filters do **not** propagate down the logger hierarchy.
          ``install_secret_masking_filters`` walks loggers that already exist and
          hooks ``Logger.manager.getLogger`` so later children get the same filter.
        - This filter causes **early formatting** of the log message (`record.getMessage()`),
          meaning `record.args` are merged into `record.msg` prematurely.
          If you rely on `record.args`, ensure this is the **last** filter in the chain.
          That incompatibility is why the env var is an escape hatch: it is read on
          every record, including after import, and skips interpolation.

    Notes:
        - The filter directly modifies `record.msg` with the masked version of the message.
        - It clears `record.args` to prevent re-formatting and ensure safe message output.

    Example:
        logger.addFilter(SecretMaskingFilter())
        handler.addFilter(SecretMaskingFilter())
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Escape hatch: do not interpolate or clear args when opted out.
        # Install-time checks cannot unwind filters already attached.
        if _log_secret_masking_disabled():
            return True
        try:
            message = record.getMessage()
            masked_data = SecretDetector.mask_secrets(message)
            record.msg = masked_data.masked_text
        except Exception:
            # Formatter-only helpers (create_formatting_error_log) need asctime,
            # which a Filter never has. Keep this path from raising into the
            # caller's logging statement.
            record.msg = _MASKING_FAILED_MSG
        finally:
            record.args = ()  # Avoid format re-application of formatting

        return True  # allow all logs through


# One instance so overlapping trees (snowflake.connector and
# snowflake.connector.vendored.urllib3) do not get two filters.
_SECRET_MASKING_FILTER = SecretMaskingFilter()


def _install_getLogger_hook() -> None:
    """Cover loggers created after install without replacing Logger.

    ``setLoggerClass`` is process-global and breaks a customer Logger whose
    ``__init__`` only accepts ``name`` (stdlib Manager calls ``klass(name)``).
    Hooking ``Manager.getLogger`` leaves the customer's class and ``__init__``
    arity alone.
    """
    global _original_manager_getLogger
    manager = logging.Logger.manager
    if _original_manager_getLogger is not None:
        return

    _original_manager_getLogger = manager.getLogger

    def hooked_getLogger(name):
        logger = _original_manager_getLogger(name)
        if (
            _name_matches_prefix(name, _hooked_prefixes)
            and _SECRET_MASKING_FILTER not in logger.filters
        ):
            logger.addFilter(_SECRET_MASKING_FILTER)
        return logger

    manager.getLogger = hooked_getLogger


def install_secret_masking_filters(logger_names: Iterable[str]) -> None:
    """Attach ``SecretMaskingFilter`` to existing and future loggers under ``logger_names``.

    This is how default-on masking is scoped: named trees only, not a
    SecretDetector Formatter on every handler. The call from
    ``externals_setup`` passes ``snowflake.connector`` plus the third-party
    loggers the connector uses (``botocore``, ``boto3``, ``aiohttp``,
    ``aiobotocore``, ``aioboto3``, vendored ``urllib3``).

    No-op when ``SNOWFLAKE_DISABLE_LOG_SECRET_MASKING=true``, so a before-import
    opt-out never patches ``getLogger``. After import, the filter itself honors
    the env var so already-attached loggers stop interpolating.
    """
    global _hooked_prefixes
    if _log_secret_masking_disabled():
        return
    _hooked_prefixes = tuple(logger_names)
    _install_getLogger_hook()
    for name in _hooked_prefixes:
        add_filter_to_logger_and_children(name, _SECRET_MASKING_FILTER)
