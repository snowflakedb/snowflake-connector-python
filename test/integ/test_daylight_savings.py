#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime

import pytest
import pytz

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def test_daylight_savings_in_TIMESTAMP_LTZ(conn_cnx, request):
    table_name = random_string(3, prefix="test_daylight_savings_in_TIMESTAMP_LTZ_")
    with conn_cnx() as cnx, cnx.cursor() as cur:
        cur.execute(f"CREATE TABLE {table_name} (c1 timestamp_ltz, "
                    f"c2 timestamp_ltz, "
                    f"c3 timestamp_ltz, "
                    f"c4 timestamp_ltz, "
                    f"c5 timestamp_ltz)")
    request.addfinalizer(drop_table(conn_cnx, table_name))
    data = [
        (datetime(year=2016, month=3, day=13, hour=18, minute=47, second=32), 'Australia/Sydney'),
        (datetime(year=2016, month=3, day=13, hour=8, minute=39, second=23), 'Europe/Paris'),
        (datetime(year=2016, month=3, day=13, hour=8, minute=39, second=23), 'UTC'),
        (datetime(year=2016, month=3, day=13, hour=1, minute=14, second=8), 'America/New_York'),
        (datetime(year=2016, month=3, day=12, hour=22, minute=32, second=4), 'US/Pacific')
    ]
    ts = [pytz.timezone(tz).localize(dt, is_dst=True) for dt, tz in data]

    insert = f"INSERT INTO {table_name} VALUES (" + ', '.join(f"'{t}'" for t in ts) + ")"
    with conn_cnx() as cnx, cnx.cursor() as cur:
        cur.execute(insert)
        result = cur.execute(f"SELECT * FROM {table_name}").fetchall()[0]
        for i in range(len(result)):
            assert result[i] == ts[i]
