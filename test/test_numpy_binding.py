import time

import numpy as np


def test_numpy_datatype_binding(conn_cnx, db_parameters):
    """
    Tests numpy data type binding
    """
    epoch_time = int(time.time()) * 1000000000 + 123456789
    all_data = [{
        'tz': 'America/Los_Angeles',
        'float': '1.79769313486e+308',
        'epoch_time': epoch_time,
        'current_time': np.datetime64(epoch_time, 'ns'),
        'specific_date': np.datetime64('2005-02-25T03:30Z')
    }, {
        'tz': 'Asia/Tokyo',
        'float': '-1.79769313486e+308',
        'epoch_time': epoch_time,
        'current_time': np.datetime64(epoch_time, 'ns'),
        'specific_date': np.datetime64('1970-12-31T05:00:00Z')
    }, {
        'tz': 'America/New_York',
        'float': '-1.79769313486e+308',
        'epoch_time': epoch_time,
        'current_time': np.datetime64(epoch_time, 'ns'),
        'specific_date': np.datetime64('1969-12-31T05:00:00Z')
    }, {
        'tz': 'UTC',
        'float': '-1.79769313486e+308',
        'epoch_time': epoch_time,
        'current_time': np.datetime64(epoch_time, 'ns'),
        'specific_date': np.datetime64('1968-11-12T07:00:00.123Z')
    }]
    try:
        with conn_cnx(use_numpy=True) as cnx:
            cnx.cursor().execute("""
CREATE OR REPLACE TABLE {name} (
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
    c11 timestamp_tz)  -- datetime64
            """.format(name=db_parameters['name']))
            for data in all_data:
                cnx.cursor().execute("""
ALTER SESSION SET timezone='{tz}'""".format(tz=data['tz']))
                cnx.cursor().execute("""
INSERT INTO {name}(
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
    c11
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
    %s)""".format(
                    name=db_parameters['name']), (
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
                ))
                rec = cnx.cursor().execute("""
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
       c11
  FROM {name}""".format(
                    name=db_parameters['name'])).fetchone()
                assert np.int8(rec[0]) == np.iinfo(np.int8).max
                assert np.int16(rec[1]) == np.iinfo(np.int16).max
                assert np.int32(rec[2]) == np.iinfo(np.int32).max
                assert np.int64(rec[3]) == np.iinfo(np.int64).max
                assert np.float16(rec[4]) == np.finfo(np.float16).max
                assert np.float32(rec[5]) == np.finfo(np.float32).max
                assert rec[6] == np.float64(data['float'])
                assert rec[7] == data['current_time']
                assert str(rec[8]) == str(data['current_time'])[0:10]
                assert rec[9] == data['current_time']
                assert rec[10] == data['specific_date']
                cnx.cursor().execute("""
DELETE FROM {name}""".format(name=db_parameters['name']))
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute("""
            DROP TABLE IF EXISTS {name}
            """.format(name=db_parameters['name']))
