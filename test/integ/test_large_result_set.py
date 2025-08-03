#!/usr/bin/env python
from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest

from snowflake.connector.secret_detector import SecretDetector
from snowflake.connector.telemetry import TelemetryField

NUMBER_OF_ROWS = 50000

PREFETCH_THREADS = [8, 3, 1]


@pytest.fixture()
def ingest_data(request, conn_cnx, db_parameters):
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
    create or replace table {name} (
        c0 int,
        c1 int,
        c2 int,
        c3 int,
        c4 int,
        c5 int,
        c6 int,
        c7 int,
        c8 int,
        c9 int)
    """.format(
                name=db_parameters["name"]
            )
        )
        cnx.cursor().execute(
            """
    insert into {name}
    select  random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100)
    from table(generator(rowCount=>{number_of_rows}))
    """.format(
                name=db_parameters["name"], number_of_rows=NUMBER_OF_ROWS
            )
        )
        first_val = (
            cnx.cursor()
            .execute(
                "select c0 from {name} order by 1 limit 1".format(
                    name=db_parameters["name"]
                )
            )
            .fetchone()[0]
        )
        last_val = (
            cnx.cursor()
            .execute(
                "select c9 from {name} order by 1 desc limit 1".format(
                    name=db_parameters["name"]
                )
            )
            .fetchone()[0]
        )

    def fin():
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )

    request.addfinalizer(fin)
    return first_val, last_val


@pytest.mark.aws
@pytest.mark.parametrize("num_threads", PREFETCH_THREADS)
def test_query_large_result_set_n_threads(
    conn_cnx, db_parameters, ingest_data, num_threads
):
    sql = "select * from {name} order by 1".format(name=db_parameters["name"])
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
        client_prefetch_threads=num_threads,
    ) as cnx:
        assert cnx.client_prefetch_threads == num_threads
        results = []
        for rec in cnx.cursor().execute(sql):
            results.append(rec)
        num_rows = len(results)
        assert NUMBER_OF_ROWS == num_rows
        assert results[0][0] == ingest_data[0]
        assert results[num_rows - 1][8] == ingest_data[1]


@pytest.mark.aws
@pytest.mark.skipolddriver
def test_query_large_result_set(conn_cnx, db_parameters, ingest_data, caplog):
    """[s3] Gets Large Result set."""
    caplog.set_level(logging.DEBUG)
    sql = "select * from {name} order by 1".format(name=db_parameters["name"])
    with conn_cnx() as cnx:
        telemetry_data = []
        add_log_mock = Mock()
        add_log_mock.side_effect = lambda datum: telemetry_data.append(datum)
        cnx._telemetry.add_log_to_batch = add_log_mock

        result2 = []
        for rec in cnx.cursor().execute(sql):
            result2.append(rec)

        num_rows = len(result2)
        assert result2[0][0] == ingest_data[0]
        assert result2[num_rows - 1][8] == ingest_data[1]

        result999 = []
        for rec in cnx.cursor().execute(sql):
            result999.append(rec)

        num_rows = len(result999)
        assert result999[0][0] == ingest_data[0]
        assert result999[num_rows - 1][8] == ingest_data[1]

        assert len(result2) == len(
            result999
        ), "result length is different: result2, and result999"
        for i, (x, y) in enumerate(zip(result2, result999)):
            assert x == y, f"element {i}"

        # verify that the expected telemetry metrics were logged
        expected = [
            TelemetryField.TIME_CONSUME_FIRST_RESULT,
            TelemetryField.TIME_CONSUME_LAST_RESULT,
            # NOTE: Arrow doesn't do parsing like how JSON does, so depending on what
            #  way this is executed only look for JSON result sets
            # TelemetryField.TIME_PARSING_CHUNKS,
            TelemetryField.TIME_DOWNLOADING_CHUNKS,
        ]
        for field in expected:
            assert (
                sum(
                    1 if x.message["type"] == field.value else 0 for x in telemetry_data
                )
                == 2
            ), (
                "Expected three telemetry logs (one per query) "
                "for log type {}".format(field.value)
            )

        aws_request_present = False
        expected_token_prefix = "X-Amz-Signature="
        for line in caplog.text.splitlines():
            if expected_token_prefix in line:
                aws_request_present = True
                # getattr is used to stay compatible with old driver - before SECRET_STARRED_MASK_STR was added
                assert (
                    expected_token_prefix
                    + getattr(SecretDetector, "SECRET_STARRED_MASK_STR", "****")
                    in line
                ), "connectionpool logger is leaking sensitive information"

        assert (
            aws_request_present
        ), "AWS URL was not found in logs, so it can't be assumed that no leaks happened in it"


@pytest.mark.aws
@pytest.mark.skipolddriver
@pytest.mark.parametrize("disable_request_pooling", [True, False])
def test_cursor_download_uses_original_http_config(
    monkeypatch, conn_cnx, ingest_data, db_parameters, disable_request_pooling
):
    """Cursor iterating after connection context ends must reuse original HTTP config."""
    from src.snowflake.connector.result_batch import ResultBatch

    download_cfgs = []
    original_download = ResultBatch._download

    def spy_download(self, connection=None, **kwargs):  # type: ignore[no-self-use]
        # Path A – batch carries its own cloned SessionManager
        if getattr(self, "_session_manager", None) is not None:
            download_cfgs.append(self._session_manager.config)
        # Path B – connection still open, _download reuses connection.rest.session_manager
        elif (
            connection is not None
            and getattr(connection, "rest", None) is not None
            and connection.rest.session_manager is not None
        ):
            download_cfgs.append(connection.rest.session_manager.config)
        return original_download(self, connection, **kwargs)

    monkeypatch.setattr(ResultBatch, "_download", spy_download, raising=True)

    table_name = db_parameters["name"]
    query_sql = f"select * from {table_name} order by 1"

    with conn_cnx(disable_request_pooling=disable_request_pooling) as conn:
        cur = conn.cursor()
        cur.execute(query_sql)
        original_cfg = conn.rest.session_manager.config

    # Connection is now closed; iterating cursor should download remaining chunks
    # It is important to make sure that all ResultBatch._download had access to either active connection's config or the one stored in self._session_manager
    list(cur)

    # Every ResultBatch download reused the same HTTP configuration values
    for cfg in download_cfgs:
        assert cfg == original_cfg
