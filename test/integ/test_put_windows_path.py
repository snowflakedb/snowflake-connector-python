#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os

from ..randomize import random_string


def test_abc(conn_cnx, tmpdir):
    """Tests PUTing a file on Windows using the URI and Windows path."""
    import pathlib
    tmp_dir = str(tmpdir.mkdir('data'))
    test_data = os.path.join(tmp_dir, 'data.txt')
    with open(test_data, 'w') as f:
        f.write("test1,test2")
        f.write("test3,test4")

    file_uri = pathlib.Path(test_data).as_uri()
    subdir = random_string(4, prefix="test_abc")

    with conn_cnx() as con:
        rec = con.cursor().execute(f"put {file_uri} @~/{subdir}0/").fetchall()
        assert rec[0][6] == 'UPLOADED'

        rec = con.cursor().execute(f"put file://{test_data} @~/{subdir}1/").fetchall()
        assert rec[0][6] == 'UPLOADED'

        con.cursor().execute("rm @~/{}0".format(subdir))
        con.cursor().execute("rm @~/{}1".format(subdir))
