#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import filecmp
import pathlib
from unittest.mock import patch

import pytest

from ..integ_helpers import put
from ..randomize import random_string

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module

try:
    from snowflake.connector.s3_storage_client import SnowflakeS3RestClient

    orig_send_req = SnowflakeS3RestClient._send_request_with_authentication_and_retry
except ImportError:
    SnowflakeS3RestClient = None
    orig_send_req = None


def _prepare_tmp_file(to_dir: str) -> str:
    tmp_dir = to_dir / "data"
    tmp_dir.mkdir()
    file_name = "data.txt"
    test_path = tmp_dir / file_name
    with test_path.open("w") as f:
        f.write("test1,test2\n")
        f.write("test3,test4")
    return test_path, file_name


def mock_send_request(
    self,
    url,
    verb,
    retry_id,
    query_parts=None,
    x_amz_headers=None,
    headers=None,
    payload=None,
    unsigned_payload=False,
    ignore_content_encoding=False,
):
    # when called under _initiate_multipart_upload and _upload_chunk, add content-encoding to header
    if verb is not None and verb in ("POST", "PUT") and headers is not None:
        headers["Content-Encoding"] = "gzip"
    return orig_send_req(
        self,
        url,
        verb,
        retry_id,
        query_parts,
        x_amz_headers,
        headers,
        payload,
        unsigned_payload,
        ignore_content_encoding,
    )


@pytest.mark.parametrize("auto_compress", [True, False])
def test_auto_compress_switch(
    tmp_path: pathlib.Path,
    conn_cnx,
    auto_compress,
):
    """Tests PUT command with auto_compress=False|True."""
    _test_name = random_string(5, "test_auto_compress_switch")
    test_data, file_name = _prepare_tmp_file(tmp_path)

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"RM @~/{_test_name}")
        try:
            file_stream = test_data.open("rb")
            with cnx.cursor() as cur:
                put(
                    cur,
                    str(test_data),
                    f"~/{_test_name}",
                    False,
                    sql_options=f"auto_compress={auto_compress}",
                    file_stream=file_stream,
                )

            ret = cnx.cursor().execute(f"LS @~/{_test_name}").fetchone()
            uploaded_gz_name = f"{file_name}.gz"
            if auto_compress:
                assert uploaded_gz_name in ret[0]
            else:
                assert uploaded_gz_name not in ret[0]

            # get this file, if the client handle compression meta correctly
            get_dir = tmp_path / "get_dir"
            get_dir.mkdir()
            cnx.cursor().execute(f"GET @~/{_test_name}/{file_name} file://{get_dir}")

            downloaded_file = get_dir / (
                uploaded_gz_name if auto_compress else file_name
            )
            assert downloaded_file.exists()
            if not auto_compress:
                assert filecmp.cmp(test_data, downloaded_file)

        finally:
            cnx.cursor().execute(f"RM @~/{_test_name}")
            if file_stream:
                file_stream.close()


@pytest.mark.aws
def test_get_gzip_content_encoding(
    tmp_path: pathlib.Path,
    conn_cnx,
):
    """Tests GET command for a content-encoding=GZIP in stage"""
    _test_name = random_string(5, "test_get_gzip_content_encoding")
    test_data, file_name = _prepare_tmp_file(tmp_path)

    with patch(
        "snowflake.connector.s3_storage_client.SnowflakeS3RestClient._send_request_with_authentication_and_retry",
        mock_send_request,
    ):
        with conn_cnx() as cnx:
            cnx.cursor().execute(f"RM @~/{_test_name}")
            try:
                file_stream = test_data.open("rb")
                with cnx.cursor() as cur:
                    put(
                        cur,
                        str(test_data),
                        f"~/{_test_name}",
                        False,
                        sql_options="auto_compress=True",
                        file_stream=file_stream,
                    )

                ret = cnx.cursor().execute(f"LS @~/{_test_name}").fetchone()
                assert f"{file_name}.gz" in ret[0]

                # get this file, if the client handle compression meta correctly
                get_dir = tmp_path / "get_dir"
                get_dir.mkdir()
                ret = (
                    cnx.cursor()
                    .execute(f"GET @~/{_test_name}/{file_name} file://{get_dir}")
                    .fetchone()
                )
                downloaded_file = get_dir / ret[0]
                assert downloaded_file.exists()

            finally:
                cnx.cursor().execute(f"RM @~/{_test_name}")
                if file_stream:
                    file_stream.close()


@pytest.mark.aws
def test_sse_get_gzip_content_encoding(
    tmp_path: pathlib.Path,
    conn_cnx,
):
    """Tests GET command for a content-encoding=GZIP in stage and it is SSE(server side encrypted)"""
    _test_name = random_string(5, "test_sse_get_gzip_content_encoding")
    test_data, orig_file_name = _prepare_tmp_file(tmp_path)
    stage_name = random_string(5, "sse_stage")
    with patch(
        "snowflake.connector.s3_storage_client.SnowflakeS3RestClient._send_request_with_authentication_and_retry",
        mock_send_request,
    ):
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                f"create or replace stage {stage_name} ENCRYPTION=(TYPE='SNOWFLAKE_SSE')"
            )
            cnx.cursor().execute(f"RM @{stage_name}/{_test_name}")
            try:
                file_stream = test_data.open("rb")
                with cnx.cursor() as cur:
                    put(
                        cur,
                        str(test_data),
                        f"{stage_name}/{_test_name}",
                        False,
                        sql_options="auto_compress=True",
                        file_stream=file_stream,
                    )

                ret = cnx.cursor().execute(f"LS @{stage_name}/{_test_name}").fetchone()
                assert f"{orig_file_name}.gz" in ret[0]

                # get this file, if the client handle compression meta correctly
                get_dir = tmp_path / "get_dir"
                get_dir.mkdir()
                ret = (
                    cnx.cursor()
                    .execute(
                        f"GET @{stage_name}/{_test_name}/{orig_file_name} file://{get_dir}"
                    )
                    .fetchone()
                )
                # TODO: The downloaded file should always be the unzip (original) file
                downloaded_file = get_dir / ret[0]
                assert downloaded_file.exists()

            finally:
                cnx.cursor().execute(f"RM @{stage_name}/{_test_name}")
                if file_stream:
                    file_stream.close()
