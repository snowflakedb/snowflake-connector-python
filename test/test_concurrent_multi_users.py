#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
"""
Concurrent test module
"""
from logging import getLogger
from multiprocessing.pool import ThreadPool

import pytest
from parameters import (CONNECTION_PARAMETERS_ADMIN)

logger = getLogger(__name__)

import snowflake.connector
from snowflake.connector.compat import TO_UNICODE


def _run_more_query(meta):
    logger.debug("running queries in %s%s", meta['user'], meta['idx'])
    cnx = meta['cnx']
    try:
        cnx.cursor().execute("""
select count(*) from (select seq8() seq from table(generator(timelimit => 4)))
        """)
        logger.debug("completed queries in %s%s", meta['user'], meta['idx'])
        return {'user': meta['user'], 'result': 1}
    except snowflake.connector.errors.ProgrammingError:
        logger.exception('failed to select')
        return {'user': meta['user'], 'result': 0}


@pytest.mark.skipif(True or not CONNECTION_PARAMETERS_ADMIN, reason="""
Flaky tests. To be fixed
""")
def test_concurrent_multiple_user_queries(conn_cnx, db_parameters):
    """
    Multithreaded multiple users tests
    """

    max_per_user = 10
    max_per_account = 20
    max_per_instance = 10
    with conn_cnx(user=db_parameters['sf_user'],
                  password=db_parameters['sf_password'],
                  account=db_parameters['sf_account']) as cnx:
        cnx.cursor().execute(
            "alter system set QUERY_GATEWAY_ENABLED=true")
        cnx.cursor().execute(
            "alter system set QUERY_GATEWAY_MAX_PER_USER={0}".format(
                max_per_user))
        cnx.cursor().execute(
            "alter system set QUERY_GATEWAY_MAX_PER_ACCOUNT={0}".format(
                max_per_account))
        cnx.cursor().execute(
            "alter system set QUERY_GATEWAY_MAX_PER_INSTANCE={0}".format(
                max_per_instance))

    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "create or replace warehouse regress1 "
                "warehouse_type='medium' warehouse_size=small")
            cnx.cursor().execute(
                "create or replace warehouse regress2 "
                "warehouse_type='medium' warehouse_size=small")
            cnx.cursor().execute("use role securityadmin")
            cnx.cursor().execute("create or replace user snowwoman "
                                 "password='test'")
            cnx.cursor().execute("use role accountadmin")
            cnx.cursor().execute("grant role sysadmin to user snowwoman")
            cnx.cursor().execute("grant all on warehouse regress2 to sysadmin")
            cnx.cursor().execute(
                "alter user snowwoman set default_role=sysadmin")

        suc_cnt1 = 0
        suc_cnt2 = 0
        with conn_cnx() as cnx1:
            with conn_cnx(user='snowwoman', password='test') as cnx2:
                cnx1.cursor().execute('use warehouse regress1')
                cnx2.cursor().execute('use warehouse regress2')

                number_of_threads = 50

                meta = []
                for i in range(number_of_threads):
                    cnx = cnx1 if i < number_of_threads / 2 else cnx2
                    user = 'A' if i < number_of_threads / 2 else 'B'
                    idx = TO_UNICODE(i + 1) \
                        if i < number_of_threads / 2 \
                        else TO_UNICODE(i + 1)
                    meta.append({'user': user, 'idx': idx, 'cnx': cnx})

                pool = ThreadPool(processes=number_of_threads)
                all_results = pool.map(_run_more_query, meta)

                assert len(all_results) == number_of_threads, \
                    'total number of jobs'
                for r in all_results:
                    if r['user'] == 'A' and r['result'] > 0:
                        suc_cnt1 += 1
                    elif r['user'] == 'B' and r['result'] > 0:
                        suc_cnt2 += 1

                logger.debug("A success: %s", suc_cnt1)
                logger.debug("B success: %s", suc_cnt2)

        # NOTE: if the previous test cancels a query, the incoming
        # query counter may not be reduced asynchrously, so
        # the maximum number of runnable queries can be one less
        assert suc_cnt1 + suc_cnt2 in (max_per_instance * 2,
                                       max_per_instance * 2 - 1), \
            'success queries for user A and B'

    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute("use role accountadmin")
            cnx.cursor().execute("drop warehouse if exists regress2")
            cnx.cursor().execute("drop warehouse if exists regress1")
            cnx.cursor().execute("use role securityadmin")
            cnx.cursor().execute("drop user if exists snowwoman")

        with conn_cnx(user=db_parameters['sf_user'],
                      password=db_parameters['sf_password'],
                      account=db_parameters['sf_account']) as cnx:
            cnx.cursor().execute(
                "alter system set QUERY_GATEWAY_MAX_PER_USER=default")
            cnx.cursor().execute(
                "alter system set QUERY_GATEWAY_MAX_PER_INSTANCE=default")
            cnx.cursor().execute(
                "alter system set QUERY_GATEWAY_MAX_PER_ACCOUNT=default")
