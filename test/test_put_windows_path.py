#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import os
import pytest

from snowflake.connector.compat import PY2

# Mark every test in this module as a putget test
pytestmark = pytest.mark.putget

@pytest.mark.skipif(PY2, reason="Python3.5 or more")
def test_abc(conn_cnx, tmpdir, db_parameters):
    """
    PUT a file on Windows using the URI and Windows path
    """
    import pathlib
    tmp_dir = str(tmpdir.mkdir('data'))
    test_data = os.path.join(tmp_dir, 'data.txt')
    with open(test_data, 'w') as f:
        f.write("test1,test2")
        f.write("test3,test4")

    fileURI = pathlib.Path(test_data).as_uri()

    subdir = db_parameters['name']
    with conn_cnx() as con:
        rec = con.cursor().execute("put {0} @~/{1}0/".format(
            fileURI, subdir)).fetchall()
        assert rec[0][6] == u'UPLOADED'

        rec = con.cursor().execute("put file://{0} @~/{1}1/".format(
            test_data, subdir)).fetchall()
        assert rec[0][6] == u'UPLOADED'

        con.cursor().execute("rm @~/{0}0".format(subdir))
        con.cursor().execute("rm @~/{0}1".format(subdir))
