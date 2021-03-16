#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import logging
from copy import deepcopy

import mock
import pytest
from pkg_resources import working_set

try:
    from snowflake.connector.options import (  # NOQA
        MissingPandas,
        _import_or_missing_pandas_option,
    )
except ImportError:
    MissingPandas = None
    _import_or_missing_pandas_option = None


@pytest.mark.skipif(
    MissingPandas is None or _import_or_missing_pandas_option is None,
    reason="No snowflake.connector.options is available. It can be the case if running old driver tests",
)
def test_pandas_option_reporting(caplog):
    """Tests for the weird case where someone can import pyarrow, but setuptools doesn't know about it.

    This issue was brought to attention in: https://github.com/snowflakedb/snowflake-connector-python/issues/412
    """
    modified_by_key = deepcopy(working_set.by_key)
    modified_by_key.pop("snowflake-connector-python")
    modified_by_key.pop("pyarrow")
    with mock.patch.object(working_set, "by_key", modified_by_key):
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        pandas, pyarrow, installed_pandas = _import_or_missing_pandas_option()
        assert installed_pandas
        assert not isinstance(pandas, MissingPandas)
        assert not isinstance(pyarrow, MissingPandas)
        assert (
            "Cannot determine if compatible pyarrow is installed because of missing package(s) "
            "from dict_keys(["
        ) in caplog.text
