import base64
import hashlib
import os
from io import BytesIO
from unittest.mock import MagicMock

from snowflake.connector import SnowflakeConnection
from snowflake.connector.azure_storage_client import SnowflakeAzureRestClient
from snowflake.connector.file_transfer_agent import SnowflakeFileMeta, StorageCredential
from snowflake.connector.storage_client import SnowflakeFileEncryptionMaterial

megabyte = 1024 * 1024

ENCRYPTION_MATERIAL = SnowflakeFileEncryptionMaterial(
    query_stage_master_key="ztke8tIdVt1zmlQIZm0BMA==",
    query_id="123873c7-3a66-40c4-ab89-e3722fbccce1",
    smk_id=3112,
)


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


def test_complete_multipart_upload_reuses_precomputed_md5_without_reading_file():
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
    client._send_request_with_authentication_and_retry = MagicMock(
        return_value=mock_response
    )

    client._complete_multipart_upload()

    _, kwargs = client._send_request_with_authentication_and_retry.call_args
    assert kwargs["headers"]["x-ms-blob-content-md5"] == base64.b64encode(
        md5_digest
    ).decode("utf-8")
    mock_response.raise_for_status.assert_called_once()


def test_compute_content_md5_for_plain_file_hashes_actual_bytes(tmp_path):
    contents = b"plain file, no encryption"
    src_file = tmp_path / "src.txt"
    src_file.write_bytes(contents)

    meta = SnowflakeFileMeta(
        name="src.txt",
        stage_location_type="AZURE",
        src_file_name=str(src_file),
        dst_file_name="src.txt",
        overwrite=True,
    )
    client = _make_client(meta)
    client.data_file = str(src_file)

    client._compute_content_md5()

    assert meta.md5_digest == hashlib.md5(contents, usedforsecurity=False).digest()


def test_compute_content_md5_for_encrypted_file_hashes_ciphertext(tmp_path):
    plaintext = b"file contents that get client-side encrypted"
    src_file = tmp_path / "src.txt"
    src_file.write_bytes(plaintext)

    meta = SnowflakeFileMeta(
        name="src.txt",
        stage_location_type="AZURE",
        src_file_name=str(src_file),
        dst_file_name="src.txt",
        encryption_material=ENCRYPTION_MATERIAL,
        overwrite=True,
    )
    client = _make_client(meta)
    client.encrypt()
    try:
        client._compute_content_md5()

        with open(client.data_file, "rb") as f:
            ciphertext = f.read()
        assert (
            meta.md5_digest == hashlib.md5(ciphertext, usedforsecurity=False).digest()
        )
        assert meta.md5_digest != hashlib.md5(plaintext, usedforsecurity=False).digest()
    finally:
        os.remove(client.data_file)


def test_compute_content_md5_for_encrypted_stream_hashes_ciphertext_and_reseeks():
    plaintext = b"stream contents that get client-side encrypted"
    meta = SnowflakeFileMeta(
        name="stream.txt",
        stage_location_type="AZURE",
        # Nonexistent on purpose: precedence must pick meta.src_stream (the
        # post-encrypt ciphertext) over ever opening this path.
        src_file_name="/nonexistent/stream.txt",
        dst_file_name="stream.txt",
        intermediate_stream=BytesIO(plaintext),
        encryption_material=ENCRYPTION_MATERIAL,
        overwrite=True,
    )
    client = _make_client(meta)
    client.encrypt()
    ciphertext = meta.src_stream.getvalue()

    client._compute_content_md5()

    assert meta.md5_digest == hashlib.md5(ciphertext, usedforsecurity=False).digest()
    assert meta.md5_digest != hashlib.md5(plaintext, usedforsecurity=False).digest()
    # The real upload reads meta.src_stream from the start next; the MD5 pass
    # must not leave it consumed at EOF.
    assert meta.src_stream.tell() == 0
