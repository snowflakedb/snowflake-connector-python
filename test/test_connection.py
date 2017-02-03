#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import pytest

import snowflake.connector
from snowflake.connector import (
    DatabaseError,
    ProgrammingError)
from snowflake.connector.errors import ForbiddenError


def test_basic(conn_testaccount):
    """
    Basic Connection test
    """
    assert conn_testaccount, 'invalid cnx'


def test_connection_without_schema(db_parameters):
    """
    Basic Connection test without schema
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_connection_without_database_schema(db_parameters):
    """
    Basic Connection test without database and schema
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_connection_without_database2(db_parameters):
    """
    Basic Connection test without database
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        schema=db_parameters['schema'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_with_config(db_parameters):
    """
    Creates a connection with the config parameter
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
    }
    cnx = snowflake.connector.connect(**config)
    assert cnx, 'invalid cnx'
    cnx.close()


def test_bad_db(db_parameters):
    """
    Attempts to use a bad DB
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        database='baddb',
    )
    assert cnx, 'invald cnx'
    cnx.close()


def test_bogus(db_parameters):
    """
    Attempts to login with invalid user name and password
    NOTE: this takes long time.
    """
    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='bogus',
            password='bogus',
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
        )

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='bogus',
            password='bogus',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
            insecure_mode=True)

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='snowman',
            password='',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
        )

    with pytest.raises(ProgrammingError):
        snowflake.connector.connect(
            protocol='http',
            user='',
            password='password',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
        )


def test_invalid_application(db_parameters):
    """
    Invalid application
    """
    with pytest.raises(snowflake.connector.Error):
        snowflake.connector.connect(
            protocol=db_parameters['protocol'],
            user=db_parameters['user'],
            password=db_parameters['password'],
            application='%%%')


def test_valid_application(db_parameters):
    """
    Valid app name
    """
    application = 'Special_Client'
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        application=application,
        protocol=db_parameters['protocol'],
    )
    assert cnx.application == application, "Must be valid application"
    cnx.close()


def test_drop_create_user(conn_cnx, db_parameters):
    """
    Drops and creates user
    """

    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe('drop user if exists snowdog')
        exe("create user if not exists snowdog identified by 'testdoc'")
        exe("use {0}".format(db_parameters['database']))
        exe("create or replace role snowdog_role")
        exe("grant role snowdog_role to user snowdog")
        exe("grant all on database {0} to role snowdog_role".format(
            db_parameters['database']))
        exe("grant all on schema {0} to role snowdog_role".format(
            db_parameters['schema']))

    with conn_cnx(user='snowdog', password='testdoc') as cnx2:
        def exe(sql):
            return cnx2.cursor().execute(sql)

        exe('use role snowdog_role')
        exe(u"use {0}".format(db_parameters['database']))
        exe(
            u"use schema {0}".format(db_parameters['schema']))
        exe(
            'create or replace table friends(name varchar(100))')
        exe('drop table friends')
    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe(
            'revoke all on database {0} from role snowdog_role'.format(
                db_parameters['database']))
        exe('drop role snowdog_role')
        exe('drop user if exists snowdog')


@pytest.mark.timeout(15)
def test_invalid_account_timeout():
    with pytest.raises(ForbiddenError):
        snowflake.connector.connect(
            account='bogus',
            user='test',
            password='test',
            login_timeout=5
        )
