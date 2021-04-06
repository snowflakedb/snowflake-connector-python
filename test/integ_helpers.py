#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover
    from snowflake.connector.cursor import SnowflakeCursor


def put(
    csr: "SnowflakeCursor",
    file_path: str,
    stage_path: str,
    from_path: bool,
    sql_options: Optional[str] = "",
    **kwargs,
) -> "SnowflakeCursor":
    """Execute PUT <file> <stage> <options> query with given cursor.

    Args:
        csr: Snowflake cursor object.
        file_path: Path to the target file in local system; Or <filename>.<extension> when from_path is False.
        stage_path: Destination path of file on the stage.
        from_path: Whether the target file is fetched with given path, specify file_stream=<IO> if False.
        sql_options: Optional arguments to the PUT command.
        **kwargs: Optional arguments passed to SnowflakeCursor.execute()

    Returns:
        A result class with the results in it. This can either be json, or an arrow result class.
    """
    sql = "put 'file://{file}' @{stage} {sql_options}"
    if from_path:
        kwargs.pop("file_stream", None)
    else:
        # PUT from stream
        file_path = os.path.basename(file_path)
    if kwargs.pop("commented", False):
        sql = "--- test comments\n" + sql
    sql = sql.format(
        file=file_path.replace("\\", "\\\\"), stage=stage_path, sql_options=sql_options
    )
    return csr.execute(sql, **kwargs)


def drop_table(
    conn_cnx: Callable[..., "SnowflakeConnection"], table: str, if_exists=False
) -> Callable:
    """Returns a function that drops <table> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object
        table: Name of table to be dropped
    """

    def _drop():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute(f"DROP TABLE IF EXISTS {table}")

    return _drop


def drop_warehouse(
    conn_cnx: Callable[..., "SnowflakeConnection"], warehouse: str
) -> Callable:
    """Returns a function that drops <warehouse> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object
        warehouse: Name of warehouse to be dropped
    """

    def _drop():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute(f"DROP WAREHOUSE IF EXISTS {warehouse}")

    return _drop


def drop_database(
    conn_cnx: Callable[..., "SnowflakeConnection"], database: str
) -> Callable:
    """Returns a function that drops <database> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object
        database: Name of database to be dropped
    """

    def _drop():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute(f"DROP DATABASE IF EXISTS {database}")

    return _drop


def drop_stage(conn_cnx: Callable[..., "SnowflakeConnection"], stage: str) -> Callable:
    """Returns a function that drops <stage> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object.
        stage: Name of stage to be dropped.
    """

    def _drop():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute(f"DROP STAGE IF EXISTS {stage}")

    return _drop


def drop_user(conn_cnx: Callable[..., "SnowflakeConnection"], user: str) -> Callable:
    """Returns a function that drops <user> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object
        user: Name of user to be dropped
    """

    def _drop():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute("USE ROLE accountadmin")
            csr.execute(f"DROP USER IF EXISTS {user}")

    return _drop


def execute(conn_cnx: Callable[..., "SnowflakeConnection"], sql: str) -> Callable:
    """Returns a function that executes <sql> in a new Snowflake connection.

    Args:
        conn_cnx: Callable to create a Snowflake Connection object
        user: Name of user to be dropped
    """

    def _execute():
        with conn_cnx() as cnx, cnx.cursor() as csr:
            csr.execute(sql)

    return _execute
