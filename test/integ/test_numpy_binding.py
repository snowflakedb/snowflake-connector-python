#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import datetime
import time

import numpy as np

from ..integ_helpers import drop_table
from ..randomize import random_string


# TODO, fails if remove DELETE FROM
def test_numpy_datatype_binding(request, conn_cnx):
    """Tests numpy data type bindings."""
    table_name = random_string(3, prefix="test_numpy_datatype_binding")
    epoch_time = time.time()
    current_datetime = datetime.datetime.fromtimestamp(epoch_time)
    current_datetime64 = np.datetime64(current_datetime)
    all_data = [{
        'tz': 'America/Los_Angeles',
        'float': '1.79769313486e+308',
        'numpy_bool': np.True_,
        'epoch_time': epoch_time,
        'current_time': current_datetime64,
        'specific_date': np.datetime64('2005-02-25T03:30'),
        'expected_specific_date': np.datetime64('2005-02-25T03:30').astype(datetime.datetime)
    }, {
        'tz': 'Asia/Tokyo',
        'float': '-1.79769313486e+308',
        'numpy_bool': np.False_,
        'epoch_time': epoch_time,
        'current_time': current_datetime64,
        'specific_date': np.datetime64('1970-12-31T05:00:00'),
        'expected_specific_date': np.datetime64('1970-12-31T05:00:00').astype(datetime.datetime)
    }, {
        'tz': 'America/New_York',
        'float': '-1.79769313486e+308',
        'numpy_bool': np.True_,
        'epoch_time': epoch_time,
        'current_time': current_datetime64,
        'specific_date': np.datetime64('1969-12-31T05:00:00'),
        'expected_specific_date': np.datetime64('1969-12-31T05:00:00').astype(datetime.datetime)
    }, {
        'tz': 'UTC',
        'float': '-1.79769313486e+308',
        'numpy_bool': np.False_,
        'epoch_time': epoch_time,
        'current_time': current_datetime64,
        'specific_date': np.datetime64('1968-11-12T07:00:00.123'),
        'expected_specific_date': np.datetime64('1968-11-12T07:00:00.123').astype(datetime.datetime)
    }]

    with conn_cnx(numpy=True) as cnx:
        cnx.cursor().execute(f"""
CREATE OR REPLACE TABLE {table_name} (
c1  integer,       -- int8
c2  integer,       -- int16
c3  integer,       -- int32
c4  integer,       -- int64
c5  float,         -- float16
c6  float,         -- float32
c7  float,         -- float64
c8  timestamp_ntz, -- datetime64
c9  date,          -- datetime64
c10 timestamp_ltz, -- datetime64,
c11 timestamp_tz,  -- datetime64
c12 boolean)       -- numpy.bool_
        """)
        request.addfinalizer(drop_table(conn_cnx, table_name))
        for data in all_data:
            cnx.cursor().execute(f"""
ALTER SESSION SET timezone='{data['tz']}'""")
            cnx.cursor().execute(f"""
INSERT INTO {table_name}(
c1,
c2,
c3,
c4,
c5,
c6,
c7,
c8,
c9,
c10,
c11,
c12
)
VALUES(
%s,
%s,
%s,
%s,
%s,
%s,
%s,
%s,
%s,
%s,
%s,
%s)""", (
                np.iinfo(np.int8).max,
                np.iinfo(np.int16).max,
                np.iinfo(np.int32).max,
                np.iinfo(np.int64).max,
                np.finfo(np.float16).max,
                np.finfo(np.float32).max,
                np.float64(data['float']),
                data['current_time'],
                data['current_time'],
                data['current_time'],
                data['specific_date'],
                data['numpy_bool']
            ))
            rec = cnx.cursor().execute(f"""
SELECT
   c1,
   c2,
   c3,
   c4,
   c5,
   c6,
   c7,
   c8,
   c9,
   c10,
   c11,
   c12
FROM {table_name}""").fetchone()
            assert np.int8(rec[0]) == np.iinfo(np.int8).max
            assert np.int16(rec[1]) == np.iinfo(np.int16).max
            assert np.int32(rec[2]) == np.iinfo(np.int32).max
            assert np.int64(rec[3]) == np.iinfo(np.int64).max
            assert np.float16(rec[4]) == np.finfo(np.float16).max
            assert np.float32(rec[5]) == np.finfo(np.float32).max
            assert rec[6] == np.float64(data['float'])
            assert rec[7] == data['current_time']
            assert str(rec[8]) == str(data['current_time'])[0:10]
            assert rec[9] == datetime.datetime.fromtimestamp(epoch_time, rec[9].tzinfo)
            assert rec[10] == data['expected_specific_date'].replace(tzinfo=rec[10].tzinfo)
            assert isinstance(rec[11], bool) and rec[11] == data['numpy_bool'] and np.bool_(rec[11]) == data[
                'numpy_bool']
            cnx.cursor().execute(f"""
DELETE FROM {table_name}""")
