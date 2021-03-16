#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger


def test_context_manager(conn_testaccount, db_parameters):
    """Tests context Manager support in Cursor."""
    logger = getLogger(__name__)

    def tables(conn):
        with conn.cursor() as cur:
            cur.execute("show tables")
            name_to_idx = {elem[0]: idx for idx, elem in enumerate(cur.description)}
            for row in cur:
                yield row[name_to_idx["name"]]

    try:
        conn_testaccount.cursor().execute(
            "create or replace table {} (a int)".format(db_parameters["name"])
        )
        all_tables = [
            rec
            for rec in tables(conn_testaccount)
            if rec == db_parameters["name"].upper()
        ]
        logger.info("tables: %s", all_tables)
        assert len(all_tables) == 1, "number of tables"
    finally:
        conn_testaccount.cursor().execute(
            "drop table if exists {}".format(db_parameters["name"])
        )
