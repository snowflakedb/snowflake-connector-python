from copy import deepcopy

import mock
from pkg_resources import working_set


def test_pandas_option_reporting(caplog):
    """Tests for the weird case where someone can import pyarrow, but setuptools doesn't know about it.

    This issue was brought to attention in: https://github.com/snowflakedb/snowflake-connector-python/issues/412
    """
    modified_by_key = deepcopy(working_set.by_key)
    modified_by_key.pop('snowflake-connector-python')
    modified_by_key.pop('pyarrow')
    with mock.patch.object(working_set, 'by_key', modified_by_key):
        from snowflake.connector.options import pandas, pyarrow, MissingPandas
        assert not isinstance(pandas, MissingPandas)
        assert not isinstance(pyarrow, MissingPandas)
        assert any([r.startswith("Cannot determine if compatible pyarrow is installed because of missing package(s) "
                                 "from dict_keys([") for r in caplog.messages])
