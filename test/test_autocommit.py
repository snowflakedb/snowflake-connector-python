#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2016 Snowflake Computing Inc. All right reserved.
#


def test_autocommit_on_off(conn_cnx, db_parameters):
    def exe0(cnx, sql):
        return cnx.cursor().execute(sql)

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=db_parameters['name']))

    with conn_cnx() as cnx:
        cnx.autocommit(False)
        try:
            exe(cnx, """
CREATE TABLE {name} (c1 boolean)
""")
            exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
            res = exe0(cnx, """
SELECT CURRENT_TRANSACTION()
""").fetchone()
            assert res[0] is not None
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE c1
""").fetchone()
            assert res[0] == 1
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
            assert res[0] == 2
            cnx.rollback()
            res = exe0(cnx, """
SELECT CURRENT_TRANSACTION()
""").fetchone()
            assert res[0] is None
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
            assert res[0] == 0
            exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
            cnx.commit()
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
            assert res[0] == 2
            cnx.rollback()
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
            assert res[0] == 2
            cnx.autocommit(True)
            exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
            cnx.rollback()
            res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
            assert res[0] == 4
        finally:
            exe(cnx, """
DROP TABLE IF EXISTS {name}
""")
