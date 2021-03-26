#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import errno
import logging
import os
from collections import defaultdict
from os import path

import mock
import OpenSSL
import pytest
from mock import MagicMock, Mock, PropertyMock

from snowflake.connector.constants import SHA256_DIGEST, ResultStatus
from snowflake.connector.s3_storage_client import (
    ERRORNO_WSAECONNABORTED,
    SnowflakeS3RestClient,
)

try:
    from snowflake.connector.file_transfer_agent import (
        SFResourceMeta,
        SnowflakeFileMeta,
    )
except ImportError:  # NOQA
    # Compatibility for olddriver tests
    SnowflakeFileMeta = dict

THIS_DIR = path.dirname(path.realpath(__file__))
MINIMAL_METADATA = SnowflakeFileMeta(
    name="file.txt",
    stage_location_type="S3",
    src_file_name="file.txt",
)


@pytest.mark.parametrize(
    "input, bucket_name, s3path",
    [
        ("sfc-dev1-regression/test_sub_dir/", "sfc-dev1-regression", "test_sub_dir/"),
        (
            "sfc-dev1-regression/stakeda/test_stg/test_sub_dir/",
            "sfc-dev1-regression",
            "stakeda/test_stg/test_sub_dir/",
        ),
        ("sfc-dev1-regression/", "sfc-dev1-regression", ""),
        ("sfc-dev1-regression//", "sfc-dev1-regression", "/"),
        ("sfc-dev1-regression///", "sfc-dev1-regression", "//"),
    ],
)
def test_extract_bucket_name_and_path(input, bucket_name, s3path):
    """Extracts bucket name and S3 path."""
    s3_util = SnowflakeS3RestClient
    s3_loc = s3_util._extract_bucket_name_and_path(input)
    assert s3_loc.bucket_name == bucket_name
    assert s3_loc.s3path == s3path


# TODO
def test_upload_one_file_to_s3_econnreset():
    """Tests Upload one file to S3 with retry on errno.ECONNRESET.

    Notes:
        The last attempted max_currency should not be changed.
    """
    for error_code in [errno.ECONNRESET, errno.ETIMEDOUT, errno.EPIPE, -1]:
        upload_file = MagicMock(
            side_effect=OpenSSL.SSL.SysCallError(
                error_code, "mock err. connection aborted"
            )
        )
        s3object = MagicMock(metadata=defaultdict(str), upload_file=upload_file)
        client = Mock()
        client.Object.return_value = s3object
        initial_parallel = 100
        client_meta = {
            "stage_info": {
                "location": "sfc-teststage/rwyitestacco/users/1234/",
                "locationType": "S3",
            },
            "cloud_client": client,
        }
        upload_meta = {
            "name": "data1.txt.gz",
            "stage_location_type": "S3",
            "no_sleeping_time": True,
            "parallel": initial_parallel,
            "put_callback": None,
            "put_callback_output_stream": None,
            SHA256_DIGEST: "123456789abcdef",
            "client_meta": SFResourceMeta(**client_meta),
            "dst_file_name": "data1.txt.gz",
            "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
            "overwrite": True,
        }
        upload_meta["real_src_file_name"] = upload_meta["src_file_name"]
        upload_meta["upload_size"] = os.stat(upload_meta["src_file_name"]).st_size
        meta = SnowflakeFileMeta(**upload_meta)
        with pytest.raises(OpenSSL.SSL.SysCallError):
            SnowflakeRemoteStorageClient.upload_file(meta)
        assert upload_file.call_count == DEFAULT_MAX_RETRY
        assert "last_max_concurrency" not in upload_meta


def test_get_s3_file_object_http_400_error():
    """Tests Get S3 file object with HTTP 400 error.

    Looks like HTTP 400 is returned when AWS token expires and S3.Object.load is called.
    """
    load_method = MagicMock(
        side_effect=botocore.exceptions.ClientError(
            {"Error": {"Code": "400", "Message": "Bad Request"}},
            operation_name="mock load",
        )
    )
    s3object = MagicMock(load=load_method)
    client = Mock()
    client.Object.return_value = s3object
    client.load.return_value = None
    type(client).s3path = PropertyMock(return_value="s3://testbucket/")
    client_meta = {
        "cloud_client": client,
        "stage_info": {
            "location": "sfc-teststage/rwyitestacco/users/1234/",
            "locationType": "S3",
        },
    }
    meta = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "client_meta": SFResourceMeta(**client_meta),
    }
    meta = SnowflakeFileMeta(**meta)
    filename = "/path1/file2.txt"
    akey = SnowflakeS3Util.get_file_header(meta, filename)
    assert akey is None
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_upload_file_with_s3_upload_failed_error():
    """Tests Upload file with S3UploadFailedError, which could indicate AWS token expires."""
    upload_file = MagicMock(
        side_effect=S3UploadFailedError(
            "An error occurred (ExpiredToken) when calling the "
            "CreateMultipartUpload operation: The provided token has expired."
        )
    )
    client = Mock()
    client.Object.return_value = MagicMock(
        metadata=defaultdict(str), upload_file=upload_file
    )
    initial_parallel = 100
    client_meta = {
        "stage_info": {
            "location": "sfc-teststage/rwyitestacco/users/1234/",
            "locationType": "S3",
        },
        "cloud_client": client,
    }
    upload_meta = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "parallel": initial_parallel,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "client_meta": SFResourceMeta(**client_meta),
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    upload_meta["real_src_file_name"] = upload_meta["src_file_name"]
    upload_meta["upload_size"] = os.stat(upload_meta["src_file_name"]).st_size
    meta = SnowflakeFileMeta(**upload_meta)

    akey = SnowflakeRemoteStorageClient.upload_file(meta)
    assert akey is None
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_get_header_expiry_error(caplog):
    """Tests whether token expiry error is handled as expected when getting header."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    meta = MINIMAL_METADATA
    mock_resource = MagicMock()
    mock_resource.load.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExpiredToken", "Message": "Just testing"}}, "Testing"
    )
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        SnowflakeS3Util.get_file_header(meta, "file.txt")
    assert (
        "snowflake.connector.s3_util",
        logging.DEBUG,
        "AWS Token expired. Renew and retry",
    ) in caplog.record_tuples
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_get_header_unexpected_error(caplog):
    """Tests whether unexpected errors are handled as expected when getting header."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    meta = MINIMAL_METADATA
    mock_resource = MagicMock()
    mock_resource.load.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "???", "Message": "Just testing"}}, "Testing"
    )
    mock_resource.bucket_name = "bucket"
    mock_resource.key = "key"
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        assert SnowflakeS3Util.get_file_header(meta, "file.txt") is None
    assert (
        "snowflake.connector.s3_util",
        logging.DEBUG,
        "Failed to get metadata for bucket, key: An error occurred (???) when calling "
        "the Testing operation: Just testing",
    ) in caplog.record_tuples
    assert meta.result_status == ResultStatus.ERROR


def test_upload_expiry_error(caplog):
    """Tests whether token expiry error is handled as expected when uploading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource, mock_object = MagicMock(), MagicMock()
    mock_resource.Object.return_value = mock_object
    mock_object.upload_file.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExpiredToken", "Message": "Just testing"}}, "Testing"
    )
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "dst_file_name": "f",
        "put_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util.extract_bucket_name_and_path"
    ):
        assert SnowflakeS3Util.upload_file("f", meta, None, 4, 67108864) is None
    assert (
        "snowflake.connector.s3_util",
        logging.DEBUG,
        "AWS Token expired. Renew and retry",
    ) in caplog.record_tuples
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_upload_unknown_error(caplog):
    """Tests whether unknown errors are handled as expected when uploading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource, mock_object = MagicMock(), MagicMock()
    mock_resource.Object.return_value = mock_object
    mock_object.bucket_name = "bucket"
    mock_object.key = "key"
    mock_object.upload_file.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "unknown", "Message": "Just testing"}}, "Testing"
    )
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "dst_file_name": "f",
        "put_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util.extract_bucket_name_and_path"
    ):
        with pytest.raises(
            botocore.exceptions.ClientError,
            match=r"An error occurred \(unknown\) when calling the Testing operation: Just testing",
        ):
            SnowflakeS3Util.upload_file("f", meta, {}, 4, 67108864)


def test_upload_failed_error(caplog):
    """Tests whether token expiry error is handled as expected when uploading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource, mock_object = MagicMock(), MagicMock()
    mock_resource.Object.return_value = mock_object
    mock_object.upload_file.side_effect = S3UploadFailedError("ExpiredToken")
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "dst_file_name": "f",
        "put_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util.extract_bucket_name_and_path"
    ):
        assert SnowflakeS3Util.upload_file("f", meta, {}, 4, 67108864) is None
    assert (
        "snowflake.connector.s3_util",
        logging.DEBUG,
        "Failed to upload a file: f, err: ExpiredToken. Renewing AWS Token and Retrying",
    ) in caplog.record_tuples
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_download_expiry_error(caplog):
    """Tests whether token expiry error is handled as expected when downloading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource = MagicMock()
    mock_resource.download_file.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ExpiredToken", "Message": "Just testing"}}, "Testing"
    )
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta_dict = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "sha256_digest": "asd",
        "client_meta": SFResourceMeta(**client_meta),
        "src_file_size": 99,
        "get_callback_output_stream": None,
        "show_progress_bar": False,
        "get_callback": None,
    }
    meta = SnowflakeFileMeta(**meta_dict)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        SnowflakeS3Util._native_download_file(meta, "f", 4)
    assert meta.result_status == ResultStatus.RENEW_TOKEN


def test_download_unknown_error(caplog):
    """Tests whether an unknown error is handled as expected when downloading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource = MagicMock()
    mock_resource.download_file.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "unknown", "Message": "Just testing"}}, "Testing"
    )
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "src_file_size": 99,
        "get_callback_output_stream": None,
        "show_progress_bar": False,
        "get_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        with pytest.raises(
            botocore.exceptions.ClientError,
            match=r"An error occurred \(unknown\) when calling the Testing operation: Just testing",
        ):
            SnowflakeS3Util._native_download_file(meta, "f", 4)
    assert (
        "snowflake.connector.s3_util",
        logging.DEBUG,
        "Failed to download a file: f, err: An error occurred (unknown) when "
        "calling the Testing operation: Just testing",
    ) in caplog.record_tuples


def test_download_retry_exceeded_error(caplog):
    """Tests whether a retry exceeded error is handled as expected when downloading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource = MagicMock()
    mock_resource.download_file.side_effect = RetriesExceededError(Boto3Error())
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "src_file_name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "src_file_size": 99,
        "get_callback_output_stream": None,
        "show_progress_bar": False,
        "get_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        SnowflakeS3Util._native_download_file(meta, "f", 4)
    assert meta.last_error is mock_resource.download_file.side_effect
    assert meta.result_status == ResultStatus.NEED_RETRY


@pytest.mark.parametrize(
    "error_no, result_status",
    [
        (ERRORNO_WSAECONNABORTED, ResultStatus.NEED_RETRY_WITH_LOWER_CONCURRENCY),
        (100, ResultStatus.NEED_RETRY),
    ],
)
def test_download_syscall_error(caplog, error_no, result_status):
    """Tests whether a syscall error is handled as expected when downloading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    mock_resource = MagicMock()
    mock_resource.download_file.side_effect = OpenSSL.SSL.SysCallError(error_no)
    client_meta = {
        "cloud_client": mock_resource,
        "stage_info": {"location": "loc"},
    }
    meta = {
        "name": "f",
        "stage_location_type": "S3",
        "client_meta": SFResourceMeta(**client_meta),
        "sha256_digest": "asd",
        "src_file_name": "f",
        "src_file_size": 99,
        "get_callback_output_stream": None,
        "show_progress_bar": False,
        "get_callback": None,
    }
    meta = SnowflakeFileMeta(**meta)
    with mock.patch(
        "snowflake.connector.s3_util.SnowflakeS3Util._get_s3_object",
        return_value=mock_resource,
    ):
        SnowflakeS3Util._native_download_file(meta, "f", 4)
    assert meta.last_error is mock_resource.download_file.side_effect
    assert meta.result_status == result_status
