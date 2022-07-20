#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os


def test_abc(conn_cnx, tmpdir, db_parameters):
    """Tests PUTing a file on Windows using the URI and Windows path."""
    import pathlib

    tmp_dir = str(tmpdir.mkdir("data"))
    test_data = os.path.join(tmp_dir, "data.txt")
    with open(test_data, "w") as f:
        f.write("test1,test2")
        f.write("test3,test4")

    fileURI = pathlib.Path(test_data).as_uri()

    subdir = db_parameters["name"]
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as con:
        rec = con.cursor().execute(f"put {fileURI} @~/{subdir}0/").fetchall()
        assert rec[0][6] == "UPLOADED"

        rec = con.cursor().execute(f"put file://{test_data} @~/{subdir}1/").fetchall()
        assert rec[0][6] == "UPLOADED"

        con.cursor().execute(f"rm @~/{subdir}0")
        con.cursor().execute(f"rm @~/{subdir}1")
