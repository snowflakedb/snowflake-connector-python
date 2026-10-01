from __future__ import annotations

import logging
import warnings
from unittest import mock

import pytest

try:
    from snowflake.connector.options import (
        MissingPandas,
        _import_or_missing_pandas_option,
        warn_if_incompatible_pyarrow,
    )
except ImportError:
    MissingPandas = None
    _import_or_missing_pandas_option = None
    warn_if_incompatible_pyarrow = None

from importlib.metadata import PackageNotFoundError, distribution

pytestmark = pytest.mark.skipif(
    MissingPandas is None
    or _import_or_missing_pandas_option is None
    or warn_if_incompatible_pyarrow is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)


@pytest.fixture(autouse=True)
def reset_pyarrow_check():
    warn_if_incompatible_pyarrow.cache_clear()
    yield
    warn_if_incompatible_pyarrow.cache_clear()


def _incompatible_pyarrow_distribution(name, *args, **kwargs):
    """Pretends pyarrow 0.0.1 is installed and the pandas extra requires pyarrow>=14.0.1."""
    if name == "pyarrow":
        return mock.Mock(version="0.0.1")
    if name == "snowflake-connector-python":
        dist = mock.Mock()
        dist.metadata.get_all.return_value = ['pyarrow>=14.0.1; extra == "pandas"']
        return dist
    return distribution(name, *args, **kwargs)


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
        warn_if_incompatible_pyarrow()
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s)"
            in caplog.text
        )
        assert "TestErrorMessage" in caplog.text


def test_import_does_not_warn_about_incompatible_pyarrow():
    """pyarrow installed by an unrelated package must not warn when the connector is imported.

    Regression test for https://github.com/snowflakedb/snowflake-connector-python/issues/2950
    """
    with mock.patch(
        "snowflake.connector.options.distribution",
        wraps=_incompatible_pyarrow_distribution,
    ), warnings.catch_warnings():
        warnings.simplefilter("error")
        _, _, installed_pandas = _import_or_missing_pandas_option()
    assert installed_pandas


def test_incompatible_pyarrow_warns_once_on_use():
    with mock.patch(
        "snowflake.connector.options.distribution",
        wraps=_incompatible_pyarrow_distribution,
    ):
        with pytest.warns(
            UserWarning, match="incompatible version of 'pyarrow' installed"
        ):
            warn_if_incompatible_pyarrow()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            warn_if_incompatible_pyarrow()


@pytest.mark.parametrize(
    "iter_unit_name, expected_calls", [("TABLE_UNIT", 1), ("ROW_UNIT", 0)]
)
def test_arrow_result_batch_checks_pyarrow_only_for_tables(
    iter_unit_name, expected_calls
):
    from snowflake.connector.constants import IterUnit
    from snowflake.connector.result_batch import ArrowResultBatch

    batch = mock.Mock(_local=True)
    with mock.patch(
        "snowflake.connector.result_batch.warn_if_incompatible_pyarrow"
    ) as check:
        ArrowResultBatch._create_iter(batch, getattr(IterUnit, iter_unit_name))
    assert check.call_count == expected_calls


def test_write_pandas_checks_pyarrow():
    from snowflake.connector import ProgrammingError
    from snowflake.connector.pandas_tools import write_pandas

    with mock.patch(
        "snowflake.connector.pandas_tools.warn_if_incompatible_pyarrow"
    ) as check:
        # database without schema fails fast, after the pyarrow check
        with pytest.raises(ProgrammingError):
            write_pandas(mock.Mock(), mock.Mock(), "table", database="db")
    check.assert_called_once_with()
