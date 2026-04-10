from __future__ import annotations

import logging
from unittest import mock

import pytest

try:
    from snowflake.connector.options import (
        MissingPandas,
        _import_or_missing_pandas_option,
    )
except ImportError:
    MissingPandas = None
    _import_or_missing_pandas_option = None

from importlib.metadata import PackageNotFoundError, distribution


@pytest.mark.skipif(
    MissingPandas is None or _import_or_missing_pandas_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pandas_option_reporting(caplog):
    """Tests for the weird case where someone can import pyarrow, but setuptools doesn't know about it.

    This issue was brought to attention in: https://github.com/snowflakedb/snowflake-connector-python/issues/412
    """

    def modified_distribution(name, *args, **kwargs):
        if name in ["pyarrow", "snowflake-connector-python"]:
            raise PackageNotFoundError("TestErrorMessage")
        return distribution(name, *args, **kwargs)

    with mock.patch(
        "snowflake.connector.options.distribution",
        wraps=modified_distribution,
    ):
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        pandas, pyarrow, installed_pandas = _import_or_missing_pandas_option()
        assert installed_pandas
        assert not isinstance(pandas, MissingPandas)
        assert not isinstance(pyarrow, MissingPandas)
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s)"
            in caplog.text
        )
        assert "TestErrorMessage" in caplog.text
