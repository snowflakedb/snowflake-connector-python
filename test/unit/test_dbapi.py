#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import time

import snowflake.connector
import snowflake.connector.dbapi
from snowflake.connector import dbapi, errors


def test_apilevel():
    try:
        apilevel = snowflake.connector.apilevel
        assert apilevel == '2.0', 'test_dbapi:test_apilevel'
    except AttributeError:
        raise Exception("test_apilevel: apilevel not defined")


def test_threadsafety():
    try:
        threadsafety = snowflake.connector.threadsafety
        assert threadsafety == 2, 'check value of threadsafety is 2'
    except errors.AttributeError:
        raise Exception("AttributeError: not defined in Snowflake.connector")


def test_paramstyle():
    assert snowflake.connector.paramstyle == 'pyformat'


def test_exceptions():
    # required exceptions should be defined in a hierarchy
    try:
        assert issubclass(errors._Warning, Exception)
    except AttributeError:
        # Compatibility for olddriver tests
        assert issubclass(errors.Warning, Exception)
    assert issubclass(errors.Error, Exception)
    assert issubclass(errors.InterfaceError, errors.Error)
    assert issubclass(errors.DatabaseError, errors.Error)
    assert issubclass(errors.OperationalError, errors.Error)
    assert issubclass(errors.IntegrityError, errors.Error)
    assert issubclass(errors.InternalError, errors.Error)
    assert issubclass(errors.ProgrammingError, errors.Error)
    assert issubclass(errors.NotSupportedError, errors.Error)


def test_STRING():
    assert hasattr(dbapi, 'STRING'), (
        'dbapi.STRING must be defined'
    )


def test_BINARY():
    assert hasattr(
        dbapi,
        'BINARY'), (
        'dbapi.BINARY must be defined.'
    )


def test_NUMBER():
    assert hasattr(
        dbapi,
        'NUMBER'), (
        'dbapi.NUMBER must be defined.'
    )


def test_DATETIME():
    assert hasattr(
        dbapi,
        'DATETIME'), (
        'dbapi.DATETIME must be defined.'
    )


def test_ROWID():
    assert hasattr(
        dbapi,
        'ROWID'), (
        'dbapi.ROWID must be defined.'
    )


def test_Date():
    d1 = snowflake.connector.dbapi.Date(
        2002, 12, 25)
    d2 = snowflake.connector.dbapi.DateFromTicks(
        time.mktime((
            2002,
            12,
            25,
            0,
            0,
            0,
            0,
            0,
            0)))
    # API doesn't specify, but it seems to be implied
    assert str(d1) == str(d2)


def test_Time():
    t1 = snowflake.connector.dbapi.Time(
        13, 45, 30)
    t2 = snowflake.connector.dbapi.TimeFromTicks(
        time.mktime(
            (
                2001, 1,
                1, 13,
                45, 30,
                0, 0,
                0)))
    # API doesn't specify, but it seems to be implied
    assert str(t1) == str(t2)


def test_Timestamp():
    t1 = snowflake.connector.dbapi.Timestamp(
        2002,
        12,
        25, 13,
        45,
        30)
    t2 = snowflake.connector.dbapi.TimestampFromTicks(
        time.mktime(
            (
                2002,
                12,
                25,
                13,
                45,
                30,
                0,
                0,
                0))
    )
    # API doesn't specify, but it seems to be implied
    assert str(t1) == str(t2)
