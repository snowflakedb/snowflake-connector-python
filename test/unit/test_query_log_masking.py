#!/usr/bin/env python
from __future__ import annotations

from snowflake.connector.connection import SnowflakeConnection


def _format(query: str, max_len: int = 10240) -> str:
    """Call _format_query_for_log on a bare connection shell (no network).

    _format_query_for_log only depends on log_max_query_length.
    """
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    conn._log_max_query_length = max_len
    return conn._format_query_for_log(query)


def test_format_query_for_log_masks_password():
    # SNOW-3675590: SQL text reaching the logs must be masked at the source.
    out = _format("SELECT 'password=SuperSecret123' AS demo")
    assert "SuperSecret123" not in out
    assert "password=****" in out


def test_format_query_for_log_masks_aws_credentials():
    sql = (
        "COPY INTO t FROM 's3://b/p' CREDENTIALS=("
        "AWS_KEY_ID='AKIAIOSFODNN7EXAMPLE' "
        "AWS_SECRET_KEY='wJalrXUtnFEMIabcdefghij1234567890ABCDEFGH')"
    )
    out = _format(sql)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "wJalrXUtnFEMIabcdefghij1234567890ABCDEFGH" not in out
    assert "AWS_KEY_ID='****'" in out
    assert "AWS_SECRET_KEY='****'" in out


def test_format_query_for_log_masks_sas_signature():
    out = _format("CREATE STAGE s URL='azure://x?sv=2021&sig=abcdef0123456789abcdef'")
    assert "abcdef0123456789abcdef" not in out
    assert "sig=****" in out


def test_format_query_for_log_leaves_innocuous_sql_untouched():
    out = _format("SELECT 1")
    assert out == "SELECT 1"


def test_format_query_for_log_still_truncates():
    out = _format("SELECT " + "a" * 50, max_len=20)
    assert out.endswith("...")
    assert len(out) == 23  # 20 chars + "..."


def test_lazy_query_log_defers_masking_until_str():
    # SNOW-3675590: the lazy wrapper must mask exactly when (and only when) it is
    # stringified, so DEBUG-disabled call sites pay no masking cost.
    from snowflake.connector.connection import _LazyQueryLog

    calls = []

    def fake_format(query: str) -> str:
        calls.append(query)
        return "MASKED"

    lazy = _LazyQueryLog(fake_format, "SELECT 'password=SuperSecret123'")
    # constructing the wrapper must not mask
    assert calls == []
    # str() triggers the masking and returns its result
    assert str(lazy) == "MASKED"
    assert calls == ["SELECT 'password=SuperSecret123'"]


def test_format_query_for_log_lazy_masks_on_str():
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    conn._log_max_query_length = 10240
    lazy = conn._format_query_for_log_lazy("SELECT 'password=SuperSecret123'")
    rendered = str(lazy)
    assert "SuperSecret123" not in rendered
    assert "password=****" in rendered
