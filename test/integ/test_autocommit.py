#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import uuid


def exe0(cnx, sql):
    return cnx.cursor().execute(sql)


def _run_autocommit_off(cnx, name):
    """Runs autocommit off test.

    Args:
        cnx: The database connection context.
        db_parameters: Database parameters.
    """

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=name))

    exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    res = exe0(
        cnx,
        """
SELECT CURRENT_TRANSACTION()
""",
    ).fetchone()
    assert res[0] is not None
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE c1
""",
    ).fetchone()
    assert res[0] == 1
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
    ).fetchone()
    assert res[0] == 2
    cnx.rollback()
    res = exe0(
        cnx,
        """
SELECT CURRENT_TRANSACTION()
""",
    ).fetchone()
    assert res[0] is None
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
    ).fetchone()
    assert res[0] == 0
    exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    cnx.commit()
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
    ).fetchone()
    assert res[0] == 2
    cnx.rollback()
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
    ).fetchone()
    assert res[0] == 2


def _run_autocommit_on(cnx, name):
    """Run autocommit on test.

    Args:
        cnx: The database connection context.
        db_parameters: Database parameters.
    """

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=name))

    exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    cnx.rollback()
    res = exe(
        cnx,
        """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
    ).fetchone()
    assert res[0] == 4


def test_autocommit_attribute(conn_cnx):
    """Tests autocommit attribute.

    Args:
        conn_cnx: The database connection context.
        db_parameters: Database parameters.
    """

    name = "python_tests_" + str(uuid.uuid4()).replace("-", "_")

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=name))

    with conn_cnx() as cnx:
        exe(
            cnx,
            """
CREATE TABLE {name} (c1 boolean)
""",
        )
        try:
            cnx.autocommit(False)
            _run_autocommit_off(cnx, name)
            cnx.autocommit(True)
            _run_autocommit_on(cnx, name)
        finally:
            exe(
                cnx,
                """
DROP TABLE IF EXISTS {name}
        """,
            )


def test_autocommit_parameters(conn_cnx):
    """Tests autocommit parameter.

    Args:
        db_parameters: Database parameters.
    """
    name = "python_tests_" + str(uuid.uuid4()).replace("-", "_")

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=name))

    with conn_cnx(
        autocommit=False,
    ) as cnx:
        exe(
            cnx,
            """
CREATE TABLE {name} (c1 boolean)
""",
        )
        _run_autocommit_off(cnx, name)

    with conn_cnx(
        autocommit=True,
    ) as cnx:
        _run_autocommit_on(cnx, name)
        exe(
            cnx,
            """
DROP TABLE IF EXISTS {name}
""",
        )
