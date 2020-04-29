import math
from typing import Callable, Generator
import pandas

import pytest

from snowflake.connector.pandas_tools import write_pandas

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from snowflake.connector import SnowflakeConnection

sf_connector_version_data = [
    ('snowflake-connector-python', '1.2.23'),
    ('snowflake-sqlalchemy', '1.1.1'),
    ('snowflake-connector-go', '0.0.1'),
    ('snowflake-go', '1.0.1'),
    ('snowflake-odbc', '3.12.3'),
]

sf_connector_version_df = pandas.DataFrame(sf_connector_version_data, columns=['name', 'newest_version'])


@pytest.mark.parametrize('chunk_size', [5, 4, 3, 2, 1])
@pytest.mark.parametrize('compression', ['gzip', 'snappy'])
# Note: since the file will to small to chunk, this is only testing the put command's syntax
@pytest.mark.parametrize('parallel', [4, 99])
def test_write_pandas(conn_cnx: Callable[..., Generator['SnowflakeConnection', None, None]],
                      compression: str,
                      parallel: int,
                      chunk_size: int):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx() as cnx:  # type: SnowflakeConnection
        table_name = 'driver_versions'
        cnx.execute_string('CREATE OR REPLACE TABLE "{}"("name" STRING, "newest_version" STRING)'.format(table_name))
        try:
            success, nchunks, nrows, _ = write_pandas(cnx,
                                                      sf_connector_version_df,
                                                      table_name,
                                                      compression=compression,
                                                      parallel=parallel,
                                                      chunk_size=chunk_size)
            if num_of_chunks == 1:
                # Note: since we used one chunk order is conserved
                assert (cnx.cursor().execute('SELECT * FROM "{}"'.format(table_name)).fetchall() ==
                        sf_connector_version_data)
            else:
                # Note: since we used one chunk order is NOT conserved
                assert (set(cnx.cursor().execute('SELECT * FROM "{}"'.format(table_name)).fetchall()) ==
                        set(sf_connector_version_data))
            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
        finally:
            cnx.execute_string("DROP TABLE IF EXISTS {}".format(table_name))
