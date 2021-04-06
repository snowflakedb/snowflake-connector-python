#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from concurrent.futures.thread import ThreadPoolExecutor
from logging import getLogger

import pytest

from snowflake.connector import ProgrammingError

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

logger = getLogger(__name__)


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_snow5871(conn_cnx, db_parameters):
    _test_snow5871(
        conn_cnx,
        db_parameters,
        number_of_threads=5,
        rt_max_outgoing_rate=60,
        rt_max_burst_size=5,
        rt_max_borrowing_limt=1000,
        rt_reset_period=10000,
    )

    _test_snow5871(
        conn_cnx,
        db_parameters,
        number_of_threads=40,
        rt_max_outgoing_rate=60,
        rt_max_burst_size=1,
        rt_max_borrowing_limt=200,
        rt_reset_period=1000,
    )


def _create_a_table(meta):
    cnx = meta["cnx"]
    name = meta["name"]
    try:
        cnx.cursor().execute(
            """
create table {} (aa int)
        """.format(
                name
            )
        )
        # print("Success #" + meta['idx'])
        return {"success": True}
    except ProgrammingError:
        logger.exception("Failed to create a table")
        return {"success": False}


def _test_snow5871(
    conn_cnx,
    db_parameters,
    number_of_threads=10,
    rt_max_outgoing_rate=60,
    rt_max_burst_size=1,
    rt_max_borrowing_limt=1000,
    rt_reset_period=10000,
):
    """SNOW-5871: rate limiting for creation of non-recycable objects."""
    logger.debug(
        (
            "number_of_threads = %s, rt_max_outgoing_rate = %s, "
            "rt_max_burst_size = %s, rt_max_borrowing_limt = %s, "
            "rt_reset_period = %s"
        ),
        number_of_threads,
        rt_max_outgoing_rate,
        rt_max_burst_size,
        rt_max_borrowing_limt,
        rt_reset_period,
    )
    with conn_cnx(
        user=db_parameters["sf_user"],
        password=db_parameters["sf_password"],
        account=db_parameters["sf_account"],
    ) as cnx:
        cnx.cursor().execute(
            """
alter system set
    RT_MAX_OUTGOING_RATE={},
    RT_MAX_BURST_SIZE={},
    RT_MAX_BORROWING_LIMIT={},
    RT_RESET_PERIOD={}""".format(
                rt_max_outgoing_rate,
                rt_max_burst_size,
                rt_max_borrowing_limt,
                rt_reset_period,
            )
        )

    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "create or replace database {name}_db".format(
                    name=db_parameters["name"]
                )
            )
            meta = []
            for i in range(number_of_threads):
                meta.append(
                    {
                        "idx": str(i + 1),
                        "cnx": cnx,
                        "name": db_parameters["name"] + "tbl_5871_" + str(i + 1),
                    }
                )
            pool = ThreadPoolExecutor(number_of_threads)
            results = list(pool.map(_create_a_table, meta))
            success = 0
            for r in results:
                success += 1 if r["success"] else 0

            # at least one should be success
            assert success >= 1, "success queries"
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop database if exists {name}_db".format(name=db_parameters["name"])
            )

        with conn_cnx(
            user=db_parameters["sf_user"],
            password=db_parameters["sf_password"],
            account=db_parameters["sf_account"],
        ) as cnx:
            cnx.cursor().execute(
                """
alter system set
    RT_MAX_OUTGOING_RATE=default,
    RT_MAX_BURST_SIZE=default,
    RT_RESET_PERIOD=default,
    RT_MAX_BORROWING_LIMIT=default"""
            )
