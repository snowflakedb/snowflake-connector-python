#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

#
# Copyright (c) 2012-2022 Snowflake Computing Inc. All rights reserved.
#
import filecmp
import pathlib
from logging import getLogger
from os import path
from unittest.mock import patch

import pytest

from snowflake.connector.s3_storage_client import SnowflakeS3RestClient

from ..integ_helpers import put

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)


def _prepare_tmp_file(to_dir: str) -> str:
    tmp_dir = to_dir / "data"
    tmp_dir.mkdir()
    file_name = "data.txt"
    test_path = tmp_dir / file_name
    with test_path.open("w") as f:
        f.write("test1,test2")
        f.write("test3,test4")
    return test_path, file_name


def _assert_str_pattern(
    no_str: str, yes_str: str, to_search_str: str, switch: bool
) -> None:
    if no_str is not None:
        assert no_str not in to_search_str
    if yes_str is not None:
        assert yes_str in to_search_str


@pytest.mark.skipolddriver
@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize("auto_compress", [True, False])
def test_auto_compress_switch(
    tmp_path: pathlib.Path,
    conn_cnx,
    auto_compress,
):
    """Tests PUT command with auto_compress=False|True."""
    _test_name = "test_auto_compress_switch"
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
            cnx.cursor().execute(
                f"GET @~/{_test_name}/{file_name} file://{get_dir}"
            ).fetchone()
            # TODO: The downloaded file should always be the unzip (original) file
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


def test_get_gzip_content_encoding(
    tmp_path: pathlib.Path,
    conn_cnx,
):
    """Tests GET command for a content-encoding=GZIP in stage"""
    _test_name = "test_get_gzip_content_encoding"
    test_data, file_name = _prepare_tmp_file(tmp_path)

    orig_send_req = SnowflakeS3RestClient._send_request_with_authentication_and_retry

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
                    ).fetchone()

                ret = cnx.cursor().execute(f"LS @~/{_test_name}").fetchone()
                assert "data.txt.gz" in ret[0]

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


def test_sse_get_gzip_content_encoding(
    tmp_path: pathlib.Path,
    conn_cnx,
):
    """Tests GET command for a content-encoding=GZIP in stage and it is SSE(server side encrypted)"""
    _test_name = "test_sse_get_gzip_content_encoding"
    tmp_dir = tmp_path / "data"
    tmp_dir.mkdir()
    orig_file_name = "data.txt"
    test_data = tmp_dir / orig_file_name
    with test_data.open("w") as f:
        f.writeln("test1,test2")
        f.write("test3,test4")
    orig_send_req = SnowflakeS3RestClient._send_request_with_authentication_and_retry

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
                assert "data.txt.gz" in ret[0]

                # get this file, if the client handle compression meta correctly
                get_dir = tmp_path / "get_dir"
                get_dir.mkdir()
                cnx.cursor().execute(
                    f"GET @~/{_test_name}/{orig_file_name} file://{get_dir}"
                ).fetchone()
                # TODO: The downloaded file should always be the unzip (original) file
                downloaded_file = get_dir / orig_file_name
                assert downloaded_file.exists()
                assert filecmp.cmp(orig_file_name, downloaded_file)

            finally:
                cnx.cursor().execute(f"RM @~/{_test_name}")
                if file_stream:
                    file_stream.close()
