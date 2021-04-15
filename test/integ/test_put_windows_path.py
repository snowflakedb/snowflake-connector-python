#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

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
        rec = con.cursor().execute("put {} @~/{}0/".format(fileURI, subdir)).fetchall()
        assert rec[0][6] == "UPLOADED"

        rec = (
            con.cursor()
            .execute("put file://{} @~/{}1/".format(test_data, subdir))
            .fetchall()
        )
        assert rec[0][6] == "UPLOADED"

        con.cursor().execute("rm @~/{}0".format(subdir))
        con.cursor().execute("rm @~/{}1".format(subdir))
