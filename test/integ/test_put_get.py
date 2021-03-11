#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import os
from logging import getLogger
from os import path

import pytest
from mock import patch

from ..integ_helpers import put
from ..randomize import random_string

try:
    from ..parameters import (CONNECTION_PARAMETERS_ADMIN)
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize("from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)])
def test_put_with_auto_compress_false(tmpdir, conn_cnx, from_path):
    """Tests PUT command with auto_compress=False."""
    tmp_dir = str(tmpdir.mkdir('data'))
    test_data = os.path.join(tmp_dir, 'data.txt')
    stage_path = random_string(5, prefix="test_put_with_auto_compress_false_")
    with open(test_data, 'w') as f:
        f.write("test1,test2")
        f.write("test3,test4")

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"RM @~/{stage_path}")
        try:
            file_stream = None if from_path else open(test_data, 'rb')
            with cnx.cursor() as cur:
                put(cur, test_data, "~/" + stage_path, from_path, sql_options="auto_compress=FALSE",
                    file_stream=file_stream)

            ret = cnx.cursor().execute(f"LS @~/{stage_path}").fetchone()
            assert f"{stage_path}/data.txt" in ret[0]
            assert "data.txt.gz" not in ret[0]
        finally:
            cnx.cursor().execute(f"RM @~/{stage_path}")
            if file_stream:
                file_stream.close()


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize("from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)])
def test_put_overwrite(tmpdir, conn_cnx, from_path):
    """Tests whether _force_put_overwrite and overwrite=true works as intended."""
    tmp_dir = str(tmpdir.mkdir('data'))
    test_data = os.path.join(tmp_dir, 'data.txt')
    stage_path = random_string(5, prefix="test_put_overwrite_")
    with open(test_data, 'w') as f:
        f.write("test1,test2")
        f.write("test3,test4")

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"RM @~/{stage_path}")
        try:
            file_stream = None if from_path else open(test_data, 'rb')
            with cnx.cursor() as cur:
                with patch.object(cur, '_init_result_and_meta', wraps=cur._init_result_and_meta) as mock_result:
                    put(cur, test_data, f"~/{stage_path}", from_path, file_stream=file_stream)
                    assert mock_result.call_args[0][0]['rowset'][0][-2] == 'UPLOADED'
                with patch.object(cur, '_init_result_and_meta', wraps=cur._init_result_and_meta) as mock_result:
                    put(cur, test_data, f"~/{stage_path}", from_path, file_stream=file_stream)
                    assert mock_result.call_args[0][0]['rowset'][0][-2] == 'SKIPPED'
                with patch.object(cur, '_init_result_and_meta', wraps=cur._init_result_and_meta) as mock_result:
                    put(cur, test_data, f"~/{stage_path}",
                        from_path, file_stream=file_stream, sql_options="OVERWRITE = TRUE")
                    assert mock_result.call_args[0][0]['rowset'][0][-2] == 'UPLOADED'

            ret = cnx.cursor().execute(f"LS @~/{stage_path}").fetchone()
            assert f"{stage_path}/{os.path.basename(test_data)}" in ret[0]
            assert os.path.basename(test_data) + ".gz" in ret[0]
        finally:
            if file_stream:
                file_stream.close()
            cnx.cursor().execute(f"RM @~/{stage_path}")


@pytest.mark.skipolddriver
def test_utf8_filename(tmpdir, is_public_test, conn_cnx):
    if is_public_test:
        pytest.skip('account missing on public CI')
    test_file = tmpdir.join("utf卡豆.csv")
    with open(str(test_file), 'w') as f:
        f.write("1,2,3\n")
    stage_name = random_string(5, 'test_utf8_filename_')
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("create temporary stage {}".format(stage_name))
            cur.execute("PUT 'file://{}' @{}".format(str(test_file).replace('\\', '/'), stage_name)).fetchall()
            cur.execute("select $1, $2, $3 from  @{}".format(stage_name))
            assert cur.fetchone() == ('1', '2', '3')


def test_put_threshold(conn_cnx, is_public_test):
    if is_public_test:
        pytest.xfail(reason="This feature hasn't been rolled out for public Snowflake deployments yet.")
    file = 'test_put_get_with_aws_token.txt.gz'

    with conn_cnx() as cnx, cnx.cursor() as cur:
        from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent
        with patch(
                'snowflake.connector.cursor.SnowflakeFileTransferAgent',
                autospec=SnowflakeFileTransferAgent
        ) as mock_agent:
            cur.execute(f"put file://{file} @~/{random_string(5)} threshold=156")
        assert mock_agent.call_args.kwargs.get('multipart_threshold', -1) == 156
