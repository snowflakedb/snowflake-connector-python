from __future__ import annotations

import io
import logging
import os
import subprocess
import sys
import textwrap
from logging import StreamHandler
from pathlib import Path

import pytest

from snowflake.connector.externals_utils.externals_setup import (
    DISABLE_LOG_SECRET_MASKING_ENV,
    add_filters_to_external_loggers,
)
from snowflake.connector.logging_utils.filters import (
    _MASKING_FAILED_MSG,
    SecretMaskingFilter,
)
from snowflake.connector.secret_detector import SecretDetector

# Values SecretDetector is known to redact (see test_retry_network.test_secret_masking).
_TOKEN = "_Y1ZNETTn5/qfUWj3Jedb"
_PASSWORD = "dummy_pass"
_SECRET_MESSAGE = f'{{"TOKEN": "{_TOKEN}", "PASSWORD": "{_PASSWORD}"}}'

_REPO_SRC = str(Path(__file__).resolve().parents[2] / "src")


def _secret_in(text: str) -> bool:
    return _TOKEN in text or _PASSWORD in text


def _emit_via_root_handler(logger: logging.Logger, msg: str) -> str:
    """Emit ``msg`` through a root StreamHandler, like ``logging.basicConfig``.

    A handler on the root logger is the documented troubleshooting setup; it
    has no SecretDetector formatter. Masking only happens if a
    SecretMaskingFilter is already on the emitting logger.
    """
    buf = io.StringIO()
    handler = StreamHandler(buf)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        logger.setLevel(logging.DEBUG)
        logger.debug(msg)
    finally:
        root.removeHandler(handler)
        handler.close()
    return buf.getvalue()


def _run_in_fresh_interpreter(
    script: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = _REPO_SRC + os.pathsep + env.get("PYTHONPATH", "")
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _iter_connector_loggers():
    yield logging.getLogger("snowflake.connector")
    for name, obj in logging.root.manager.loggerDict.items():
        if name.startswith("snowflake.connector.") and isinstance(obj, logging.Logger):
            yield obj


def _strip_secret_masking_filters() -> None:
    for logger in _iter_connector_loggers():
        for flt in list(logger.filters):
            if isinstance(flt, SecretMaskingFilter):
                logger.removeFilter(flt)
        for handler in logger.handlers:
            for flt in list(handler.filters):
                if isinstance(flt, SecretMaskingFilter):
                    handler.removeFilter(flt)


@pytest.fixture
def restore_secret_masking():
    """Re-apply default masking after tests that strip or skip it.

    Clears the opt-out env var before re-attaching so this fixture's teardown
    (which runs before monkeypatch restores the env) does not no-op.
    """
    yield
    os.environ.pop(DISABLE_LOG_SECRET_MASKING_ENV, None)
    _strip_secret_masking_filters()
    add_filters_to_external_loggers()


def test_connector_logs_are_masked_under_standard_logging_config():
    """Masking applies without save_logs / Easy Logging (SNOW-3675583)."""
    logger = logging.getLogger("snowflake.connector.network")
    text = _emit_via_root_handler(logger, _SECRET_MESSAGE)
    assert not _secret_in(text)
    assert SecretDetector.SECRET_STARRED_MASK_STR in text


def test_lazy_child_logger_is_masked():
    """Loggers created after import still get masking (filters do not propagate)."""
    logger = logging.getLogger("snowflake.connector._test_lazy_secret_masking")
    text = _emit_via_root_handler(logger, _SECRET_MESSAGE)
    assert not _secret_in(text)
    assert SecretDetector.SECRET_STARRED_MASK_STR in text


def test_lazy_third_party_child_logger_is_masked():
    """The getLogger hook covers MODULES_TO_MASK_LOGS_NAMES, not only snowflake.connector.*."""
    logger = logging.getLogger("botocore._test_lazy_secret_masking")
    text = _emit_via_root_handler(logger, _SECRET_MESSAGE)
    assert not _secret_in(text)
    assert SecretDetector.SECRET_STARRED_MASK_STR in text


def test_child_logger_own_handler_is_masked():
    logger = logging.getLogger("snowflake.connector._test_own_handler")
    buf = io.StringIO()
    handler = StreamHandler(buf)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    previous_propagate = logger.propagate
    logger.propagate = False
    try:
        logger.setLevel(logging.DEBUG)
        logger.debug(_SECRET_MESSAGE)
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.propagate = previous_propagate
    text = buf.getvalue()
    assert not _secret_in(text)
    assert SecretDetector.SECRET_STARRED_MASK_STR in text


def test_innocuous_message_is_unchanged():
    logger = logging.getLogger("snowflake.connector.network")
    msg = "connecting to account test_account"
    text = _emit_via_root_handler(logger, msg)
    assert msg in text


def test_masking_filter_clears_record_args():
    record = logging.LogRecord(
        "snowflake.connector.network",
        logging.DEBUG,
        __file__,
        0,
        "password=%s",
        (_PASSWORD,),
        None,
    )
    assert SecretMaskingFilter().filter(record) is True
    assert record.args == ()
    assert _PASSWORD not in str(record.msg)
    assert SecretDetector.SECRET_STARRED_MASK_STR in str(record.msg)


def test_filter_does_not_raise_when_message_formatting_fails():
    record = logging.LogRecord(
        "snowflake.connector.network",
        logging.DEBUG,
        __file__,
        0,
        "%s %s",
        ("only-one-arg",),
        None,
    )
    assert not hasattr(record, "asctime")
    assert SecretMaskingFilter().filter(record) is True
    assert record.args == ()
    assert record.msg == _MASKING_FAILED_MSG


def test_setLoggerClass_after_import_still_masks_lazy_child():
    previous = logging.getLoggerClass()

    class AfterImportLogger(logging.Logger):
        def __init__(self, name, level=logging.NOTSET):
            super().__init__(name, level)

    try:
        logging.setLoggerClass(AfterImportLogger)
        logger = logging.getLogger("snowflake.connector._test_after_logger_class")
        assert type(logger) is AfterImportLogger
        text = _emit_via_root_handler(logger, _SECRET_MESSAGE)
        assert not _secret_in(text)
        assert SecretDetector.SECRET_STARRED_MASK_STR in text
    finally:
        logging.setLoggerClass(previous)


def test_opt_out_env_var_skips_masking(monkeypatch, restore_secret_masking):
    """Escape hatch: setting the env after import must stop masking in place."""
    monkeypatch.setenv(DISABLE_LOG_SECRET_MASKING_ENV, "true")

    logger = logging.getLogger("snowflake.connector.network")
    text = _emit_via_root_handler(logger, _SECRET_MESSAGE)
    assert _secret_in(text)

    lazy = logging.getLogger("snowflake.connector._test_opt_out_lazy")
    lazy_text = _emit_via_root_handler(lazy, _SECRET_MESSAGE)
    assert _secret_in(lazy_text)


def test_opt_out_preserves_record_args(monkeypatch, restore_secret_masking):
    """The incompatibility this hatch exists for: do not interpolate or clear args."""
    monkeypatch.setenv(DISABLE_LOG_SECRET_MASKING_ENV, "true")
    record = logging.LogRecord(
        "snowflake.connector.network",
        logging.DEBUG,
        __file__,
        0,
        "password=%s",
        (_PASSWORD,),
        None,
    )
    logger = logging.getLogger("snowflake.connector.network")
    attached = [flt for flt in logger.filters if isinstance(flt, SecretMaskingFilter)]
    assert attached, "expected SecretMaskingFilter to already be on the logger"
    assert attached[0].filter(record) is True
    assert record.args == (_PASSWORD,)
    assert record.msg == "password=%s"


def test_opt_out_before_import_in_subprocess():
    """Before-import opt-out skips installing the getLogger hook entirely."""
    script = textwrap.dedent(
        f"""
        import io
        import logging
        from logging import StreamHandler

        import snowflake.connector

        token = {_TOKEN!r}
        password = {_PASSWORD!r}
        msg = '{{"TOKEN": "' + token + '", "PASSWORD": "' + password + '"}}'
        logger = logging.getLogger("snowflake.connector.network")
        buf = io.StringIO()
        handler = StreamHandler(buf)
        handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.debug(msg)
        text = buf.getvalue()
        if token not in text and password not in text:
            raise SystemExit("masked despite opt-out: " + repr(text))
        print("UNMASKED_OK")
        """
    )
    proc = _run_in_fresh_interpreter(
        script, extra_env={DISABLE_LOG_SECRET_MASKING_ENV: "true"}
    )
    assert proc.returncode == 0, proc.stderr
    assert "UNMASKED_OK" in proc.stdout


def test_opt_out_after_import_in_subprocess():
    """Escape hatch: set the env after import and already-attached filters no-op."""
    script = textwrap.dedent(
        f"""
        import io
        import logging
        import os
        from logging import StreamHandler

        import snowflake.connector

        os.environ[{DISABLE_LOG_SECRET_MASKING_ENV!r}] = "true"

        token = {_TOKEN!r}
        password = {_PASSWORD!r}
        msg = '{{"TOKEN": "' + token + '", "PASSWORD": "' + password + '"}}'
        logger = logging.getLogger("snowflake.connector.network")
        buf = io.StringIO()
        handler = StreamHandler(buf)
        handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.debug(msg)
        text = buf.getvalue()
        if token not in text and password not in text:
            raise SystemExit("masked despite post-import opt-out: " + repr(text))
        print("UNMASKED_OK")
        """
    )
    proc = _run_in_fresh_interpreter(script)
    assert proc.returncode == 0, proc.stderr
    assert "UNMASKED_OK" in proc.stdout


def test_one_arg_logger_class_before_import_still_masks():
    """Customer setLoggerClass(__init__(self, name)) must not break getLogger."""
    script = textwrap.dedent(
        f"""
        import io
        import logging
        from logging import StreamHandler

        class OneArgLogger(logging.Logger):
            def __init__(self, name):
                super().__init__(name)

        logging.setLoggerClass(OneArgLogger)

        import snowflake.connector  # noqa: F401

        logging.getLogger("unrelated.after_import")

        token = {_TOKEN!r}
        password = {_PASSWORD!r}
        msg = '{{"TOKEN": "' + token + '", "PASSWORD": "' + password + '"}}'
        logger = logging.getLogger("snowflake.connector.network")
        buf = io.StringIO()
        handler = StreamHandler(buf)
        handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.debug(msg)
        text = buf.getvalue()
        if token in text or password in text:
            raise SystemExit("unmasked: " + repr(text))
        print("OK")
        """
    )
    proc = _run_in_fresh_interpreter(script)
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
