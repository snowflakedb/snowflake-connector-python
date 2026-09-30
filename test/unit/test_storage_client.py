from os import path
from unittest.mock import MagicMock

try:
    from snowflake.connector import SnowflakeConnection
    from snowflake.connector.constants import ResultStatus
    from snowflake.connector.file_transfer_agent import (
        SnowflakeFileMeta,
        StorageCredential,
    )
    from snowflake.connector.s3_storage_client import SnowflakeS3RestClient
except ImportError:
    # Compatibility for olddriver tests
    from snowflake.connector.s3_util import ERRORNO_WSAECONNABORTED  # NOQA

    SnowflakeFileMeta = dict
    SnowflakeS3RestClient = None
    RequestExceedMaxRetryError = None
    StorageCredential = None
    megabytes = 1024 * 1024
    DEFAULT_MAX_RETRY = 5

THIS_DIR = path.dirname(path.realpath(__file__))
megabyte = 1024 * 1024


def test_status_when_num_of_chunks_is_zero():
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        "sha256_digest": "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    rest_client.successful_transfers = 0
    rest_client.num_of_chunks = 0
    rest_client.finish_upload()
    assert meta.result_status == ResultStatus.ERROR


def _make_s3_client(meta: SnowflakeFileMeta) -> SnowflakeS3RestClient:
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    return SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )


def test_get_digest_does_not_compute_md5():
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    rest_client = _make_s3_client(meta)

    rest_client.get_digest()

    assert meta.sha256_digest is not None
    assert meta.md5_digest is None


def test_compute_content_md5_is_noop_by_default():
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    rest_client = _make_s3_client(meta)

    rest_client._compute_content_md5()

    assert meta.md5_digest is None
