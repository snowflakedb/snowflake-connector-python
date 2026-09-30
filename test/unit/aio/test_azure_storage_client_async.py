import base64
from unittest.mock import AsyncMock, MagicMock

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.aio._azure_storage_client import SnowflakeAzureRestClient
from snowflake.connector.aio._file_transfer_agent import SnowflakeFileMeta
from snowflake.connector.file_transfer_agent import StorageCredential

megabyte = 1024 * 1024


def _make_client(meta: SnowflakeFileMeta) -> SnowflakeAzureRestClient:
    creds = {"AZURE_SAS_TOKEN": "sv=2021-08-06"}
    return SnowflakeAzureRestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        4 * megabyte,
        {
            "locationType": "AZURE",
            "location": "container/path",
            "creds": creds,
            "storageAccount": "sfcaccount",
            "endPoint": "blob.core.windows.net",
        },
    )


async def test_complete_multipart_upload_reuses_precomputed_md5_without_reading_file():
    md5_digest = b"0123456789abcdef"
    meta = SnowflakeFileMeta(
        name="big_file.txt",
        stage_location_type="AZURE",
        # Nonexistent on purpose: a regression that re-reads the source file
        # to recompute the MD5 (SNOW-4168830) fails loudly with
        # FileNotFoundError instead of passing silently.
        src_file_name="/nonexistent/big_file.txt",
        dst_file_name="big_file.txt",
        sha256_digest="deadbeef",
        md5_digest=md5_digest,
        overwrite=True,
    )
    client = _make_client(meta)
    client.block_ids = ["block0", "block1"]

    mock_response = MagicMock()
    client._send_request_with_authentication_and_retry = AsyncMock(
        return_value=mock_response
    )

    await client._complete_multipart_upload()

    _, kwargs = client._send_request_with_authentication_and_retry.call_args
    assert kwargs["headers"]["x-ms-blob-content-md5"] == base64.b64encode(
        md5_digest
    ).decode("utf-8")
    mock_response.raise_for_status.assert_called_once()
