#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import logging
import time
from logging import getLogger
from threading import Lock, Thread

import pytest

from snowflake.connector import errors

logger = getLogger(__name__)
logging.basicConfig(level=logging.CRITICAL)

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.fixture()
def conn_cnx(request, conn_cnx):
    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute("use role accountadmin")
            cnx.cursor().execute("drop user magicuser1")
            cnx.cursor().execute("drop user magicuser2")

    request.addfinalizer(fin)

    with conn_cnx() as cnx:
        cnx.cursor().execute("use role securityadmin")
        cnx.cursor().execute(
            "create or replace user magicuser1 password='xxx' " "default_role='PUBLIC'"
        )
        cnx.cursor().execute(
            "create or replace user magicuser2 password='xxx' " "default_role='PUBLIC'"
        )

    return conn_cnx


def _query_run(conn, shared, expectedCanceled=True):
    """Runs a query, and wait for possible cancellation."""
    with conn(user="magicuser1", password="xxx") as cnx:
        cnx.cursor().execute("use warehouse regress")

        # Collect the session_id
        with cnx.cursor() as c:
            c.execute("SELECT current_session()")
            for rec in c:
                with shared.lock:
                    shared.session_id = int(rec[0])
        logger.info("Current Session id: {}".format(shared.session_id))

        # Run a long query and see if we're canceled
        canceled = False
        try:
            c = cnx.cursor()
            c.execute(
                """
select count(*) from table(generator(timeLimit => 10))"""
            )
        except errors.ProgrammingError as e:
            logger.info("FAILED TO RUN QUERY: %s", e)
            canceled = e.errno == 604
            if not canceled:
                logger.exception("must have been canceled")
                raise
        finally:
            c.close()

        if canceled:
            logger.info("Query failed or was canceled")
        else:
            logger.info("Query finished successfully")

        assert canceled == expectedCanceled


def _query_cancel(conn, shared, user, password, expectedCanceled):
    """Tests cancelling the query running in another thread."""
    with conn(user=user, password=password) as cnx:
        cnx.cursor().execute("use warehouse regress")
        # .use_warehouse_database_schema(cnx)

        logger.info(
            "User %s's role is: %s",
            user,
            cnx.cursor().execute("select current_role()").fetchone()[0],
        )
        # Run the cancel query
        logger.info("User %s is waiting for Session ID to be available", user)
        while True:
            with shared.lock:
                if shared.session_id is not None:
                    break
            logger.info("User %s is waiting for Session ID to be available", user)
            time.sleep(1)
        logger.info("Target Session id: {}".format(shared.session_id))
        try:
            query = "call system$cancel_all_queries({})".format(shared.session_id)
            logger.info("Query: %s", query)
            cnx.cursor().execute(query)
            assert (
                expectedCanceled
            ), "You should NOT be able to " "cancel the query [{}]".format(
                shared.session_id
            )
        except errors.ProgrammingError as e:
            logger.info("FAILED TO CANCEL THE QUERY: %s", e)
            assert (
                not expectedCanceled
            ), "You should be able to " "cancel the query [{}]".format(
                shared.session_id
            )


def _test_helper(conn, expectedCanceled, cancelUser, cancelPass):
    """Helper function for the actual tests.

    queryRun is always run with magicuser1/xxx.
    queryCancel is run with cancelUser/cancelPass
    """

    class Shared(object):
        def __init__(self):
            self.lock = Lock()
            self.session_id = None

    shared = Shared()
    queryRun = Thread(target=_query_run, args=(conn, shared, expectedCanceled))
    queryRun.start()
    queryCancel = Thread(
        target=_query_cancel,
        args=(conn, shared, cancelUser, cancelPass, expectedCanceled),
    )
    queryCancel.start()
    queryCancel.join(5)
    queryRun.join(20)


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_same_user_canceling(conn_cnx):
    """Tests that the same user CAN cancel his own query."""
    _test_helper(conn_cnx, True, "magicuser1", "xxx")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_other_user_canceling(conn_cnx):
    """Tests that the other user CAN NOT cancel his own query."""
    _test_helper(conn_cnx, False, "magicuser2", "xxx")
