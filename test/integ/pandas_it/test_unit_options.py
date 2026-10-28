from __future__ import annotations

import logging
from unittest import mock

import pytest

try:
    from snowflake.connector.options import (
        MissingOptionalDependency,
        MissingPandas,
        MissingPyarrow,
        _import_or_missing_pandas_option,
        missing_pandas_extra_message,
    )
except ImportError:
    MissingOptionalDependency = None
    MissingPandas = None
    MissingPyarrow = None
    _import_or_missing_pandas_option = None
    missing_pandas_extra_message = None

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
        assert not isinstance(pyarrow, MissingPyarrow)
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s)"
            in caplog.text
        )
        assert "TestErrorMessage" in caplog.text


@pytest.mark.skipif(
    MissingPyarrow is None or _import_or_missing_pandas_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_import_reports_missing_pyarrow_separately():
    """pandas alone is not enough; a missing pyarrow must be named in the result."""
    real_import_module = __import__("importlib").import_module

    def fake_import_module(name, *args, **kwargs):
        if name == "pyarrow":
            raise ImportError("simulated missing pyarrow")
        return real_import_module(name, *args, **kwargs)

    with mock.patch(
        "snowflake.connector.options.importlib.import_module",
        side_effect=fake_import_module,
    ):
        pandas, pyarrow, installed_pandas = _import_or_missing_pandas_option()

    assert installed_pandas is False
    assert not isinstance(pandas, MissingOptionalDependency)
    assert isinstance(pyarrow, MissingPyarrow)


@pytest.mark.skipif(
    missing_pandas_extra_message is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_missing_pandas_extra_message_names_pyarrow():
    """Error text must blame pyarrow when only pyarrow failed to import."""
    with mock.patch(
        "snowflake.connector.options.pandas",
        object(),
    ), mock.patch(
        "snowflake.connector.options.pyarrow",
        MissingPyarrow(),
    ):
        msg = missing_pandas_extra_message()
    assert "'pyarrow'" in msg
    assert "'pandas'" not in msg
    assert "python-connector-pandas.html" in msg
