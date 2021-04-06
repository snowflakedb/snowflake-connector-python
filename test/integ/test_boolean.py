#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#


def test_binding_fetching_boolean(conn_cnx, db_parameters):
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
create or replace table {name} (c1 boolean, c2 integer)
""".format(
                    name=db_parameters["name"]
                )
            )

        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
insert into {name} values(%s,%s), (%s,%s), (%s,%s)
""".format(
                    name=db_parameters["name"]
                ),
                (True, 1, False, 2, True, 3),
            )
            results = (
                cnx.cursor()
                .execute(
                    """
select * from {name} order by 1""".format(
                        name=db_parameters["name"]
                    )
                )
                .fetchall()
            )
            assert not results[0][0]
            assert results[1][0]
            assert results[2][0]
            results = (
                cnx.cursor()
                .execute(
                    """
select c1 from {name} where c2=2
""".format(
                        name=db_parameters["name"]
                    )
                )
                .fetchall()
            )
            assert not results[0][0]

            # SNOW-15905: boolean support
            results = (
                cnx.cursor()
                .execute(
                    """
SELECT CASE WHEN (null LIKE trim(null)) THEN null  ELSE null END
"""
                )
                .fetchall()
            )
            assert not results[0][0]

    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


def test_boolean_from_compiler(conn_cnx):
    with conn_cnx() as cnx:
        ret = cnx.cursor().execute("SELECT true").fetchone()
        assert ret[0]

        ret = cnx.cursor().execute("SELECT false").fetchone()
        assert not ret[0]
