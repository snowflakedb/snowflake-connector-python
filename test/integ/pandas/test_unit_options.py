#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

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

from importlib.metadata import distributions


@pytest.mark.skipif(
    MissingPandas is None or _import_or_missing_pandas_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pandas_option_reporting(caplog):
    """Tests for the weird case where someone can import pyarrow, but setuptools doesn't know about it.

    This issue was brought to attention in: https://github.com/snowflakedb/snowflake-connector-python/issues/412
    """
    modified_distributions = list(
        d
        for d in distributions()
        if d.metadata["Name"]
        not in (
            "pyarrow",
            "snowflake-connecctor-python",
        )
    )
    with mock.patch(
        "snowflake.connector.options.distributions",
        return_value=modified_distributions,
    ):
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        pandas, pyarrow, installed_pandas = _import_or_missing_pandas_option()
        assert installed_pandas
        assert not isinstance(pandas, MissingPandas)
        assert not isinstance(pyarrow, MissingPandas)
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s) "
            "from "
        ) in caplog.text
