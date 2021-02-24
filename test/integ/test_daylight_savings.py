#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime

import pytz


def _insert_timestamp(ctx, table, tz, dt):
    myzone = pytz.timezone(tz)
    ts = myzone.localize(dt, is_dst=True)
    print("\n")
    print("{}".format(repr(ts)))
    ctx.cursor().execute(
        "INSERT INTO {table} VALUES(%s)".format(
            table=table,
        ),
        (ts,),
    )

    result = (
        ctx.cursor().execute("SELECT * FROM {table}".format(table=table)).fetchone()
    )
    retrieved_ts = result[0]
    print("#####")
    print("Retrieved ts: {}".format(repr(retrieved_ts)))
    print("Retrieved and converted TS{}".format(repr(retrieved_ts.astimezone(myzone))))
    print("#####")
    assert result[0] == ts
    ctx.cursor().execute("DELETE FROM {table}".format(table=table))


def test_daylight_savings_in_TIMESTAMP_LTZ(conn_cnx, db_parameters):
    with conn_cnx() as ctx:
        ctx.cursor().execute(
            "CREATE OR REPLACE TABLE {table} (c1 timestamp_ltz)".format(
                table=db_parameters["name"],
            )
        )
        try:
            dt = datetime(year=2016, month=3, day=13, hour=18, minute=47, second=32)
            _insert_timestamp(ctx, db_parameters["name"], "Australia/Sydney", dt)
            dt = datetime(year=2016, month=3, day=13, hour=8, minute=39, second=23)
            _insert_timestamp(ctx, db_parameters["name"], "Europe/Paris", dt)
            dt = datetime(year=2016, month=3, day=13, hour=8, minute=39, second=23)
            _insert_timestamp(ctx, db_parameters["name"], "UTC", dt)

            dt = datetime(year=2016, month=3, day=13, hour=1, minute=14, second=8)
            _insert_timestamp(ctx, db_parameters["name"], "America/New_York", dt)

            dt = datetime(year=2016, month=3, day=12, hour=22, minute=32, second=4)
            _insert_timestamp(ctx, db_parameters["name"], "US/Pacific", dt)

        finally:
            ctx.cursor().execute(
                "DROP TABLE IF EXISTS {table}".format(
                    table=db_parameters["name"],
                )
            )
