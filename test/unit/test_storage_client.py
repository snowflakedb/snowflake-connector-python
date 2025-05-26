from os import path
from unittest.mock import MagicMock, patch

from snowflake.connector import SnowflakeConnection
from snowflake.connector.vendored.urllib3.util import ssl_wrap_socket

try:
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

    ssl_wrap_socket.FEATURE_ROOT_CERTS_DICT_LOCK_TIMEOUT = "test"

    with patch(
        "snowflake.connector.vendored.urllib3.util.ssl_wrap_socket.FEATURE_ROOT_CERTS_DICT_LOCK_TIMEOUT"
    ) as mock_lock_timeout:
        mock_lock_timeout.return_value = "test"
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
