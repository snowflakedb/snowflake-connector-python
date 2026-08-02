from __future__ import annotations

import logging
import warnings
from unittest import mock

import pytest

try:
    from snowflake.connector.options import (
        MissingPyArrow,
        _import_or_missing_pyarrow_option,
    )
except ImportError:
    MissingPyArrow = None
    _import_or_missing_pyarrow_option = None

from importlib.metadata import PackageNotFoundError, distribution


@pytest.mark.skipif(
    MissingPyArrow is None or _import_or_missing_pyarrow_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pyarrow_option_reporting(caplog):
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
        pyarrow, installed_pyarrow = _import_or_missing_pyarrow_option()
        assert installed_pyarrow
        assert not isinstance(pyarrow, MissingPyArrow)
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s)"
            in caplog.text
        )
        assert "TestErrorMessage" in caplog.text


@pytest.mark.skipif(
    MissingPyArrow is None or _import_or_missing_pyarrow_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pyarrow_version_check_reads_arrow_extra():
    """The supported pyarrow range comes from the arrow extra's pin."""
    pyarrow_dist = mock.Mock(version="2.0.0")
    connector_dist = mock.Mock()
    connector_dist.metadata.get_all.return_value = [
        'pyarrow>=1; extra == "pandas"',
        'pyarrow<1; extra == "arrow"',
    ]

    def modified_distribution(name):
        if name == "pyarrow":
            return pyarrow_dist
        if name == "snowflake-connector-python":
            return connector_dist
        return distribution(name)

    with mock.patch(
        "snowflake.connector.options.distribution",
        wraps=modified_distribution,
    ):
        with pytest.warns(UserWarning, match="pyarrow<1"):
            pyarrow, installed_pyarrow = _import_or_missing_pyarrow_option()

    assert installed_pyarrow
    assert not isinstance(pyarrow, MissingPyArrow)


@pytest.mark.skipif(
    MissingPyArrow is None or _import_or_missing_pyarrow_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pyarrow_version_check_tolerates_metadata_without_arrow_extra():
    """Metadata predating the arrow extra must not warn or break the import."""
    connector_dist = mock.Mock()
    connector_dist.metadata.get_all.return_value = ['pyarrow>=1; extra == "pandas"']

    def modified_distribution(name):
        if name == "snowflake-connector-python":
            return connector_dist
        return distribution(name)

    with mock.patch(
        "snowflake.connector.options.distribution",
        wraps=modified_distribution,
    ):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            pyarrow, installed_pyarrow = _import_or_missing_pyarrow_option()

    assert installed_pyarrow
    assert not isinstance(pyarrow, MissingPyArrow)
