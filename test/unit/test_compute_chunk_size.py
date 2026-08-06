import pytest

pytestmark = pytest.mark.skipolddriver


def test_check_chunk_size():
    from snowflake.connector.constants import (
        S3_MAX_OBJECT_SIZE,
        S3_MAX_PART_SIZE,
        S3_MIN_PART_SIZE,
    )
    from snowflake.connector.file_transfer_agent import _chunk_size_calculator

    expected_chunk_size = 8 * 1024**2
    sample_file_size_2gb = 2 * 1024**3
    sample_file_size_under_5tb = 4.9 * 1024**4
    sample_file_size_6tb = 6 * 1024**4
    sample_chunk_size_4mb = 4 * 1024**2

    chunk_size_1 = _chunk_size_calculator(sample_file_size_2gb)
    assert chunk_size_1 == expected_chunk_size

    chunk_size_2 = _chunk_size_calculator(int(sample_file_size_under_5tb))
    assert chunk_size_2 <= S3_MAX_PART_SIZE

    with pytest.raises(ValueError) as exc:
        _chunk_size_calculator(sample_file_size_6tb)
    assert (
        f"File size {sample_file_size_6tb} exceeds the maximum allowed file size {S3_MAX_OBJECT_SIZE}."
        in str(exc)
    )

    chunk_size_1 = _chunk_size_calculator(sample_chunk_size_4mb)
    assert chunk_size_1 >= S3_MIN_PART_SIZE


def test_check_azure_chunk_size():
    import math

    from snowflake.connector.constants import (
        AZURE_CHUNK_SIZE,
        AZURE_MAX_BLOCKS,
        AZURE_MAX_OBJECT_SIZE,
    )
    from snowflake.connector.file_transfer_agent import _chunk_size_calculator

    def azure_chunk_size(file_size: int) -> int:
        return _chunk_size_calculator(
            file_size,
            default_chunk_size=AZURE_CHUNK_SIZE,
            max_parts=AZURE_MAX_BLOCKS,
            min_part_size=AZURE_CHUNK_SIZE,
            max_object_size=AZURE_MAX_OBJECT_SIZE,
        )

    gigabyte = 1024**3

    # Small/medium files keep the default 8 MB chunk size.
    assert azure_chunk_size(1 * gigabyte) == AZURE_CHUNK_SIZE

    # 300 GB used to require ~78,600 blocks at 4 MB (over the 50,000 limit); at
    # 8 MB it stays well under the limit without any scaling.
    chunk_size_300gb = azure_chunk_size(300 * gigabyte)
    assert chunk_size_300gb == AZURE_CHUNK_SIZE
    assert math.ceil(300 * gigabyte / chunk_size_300gb) <= AZURE_MAX_BLOCKS

    # Very large files scale the chunk size up so the block count stays within
    # the Azure 50,000-block limit.
    chunk_size_1tb = azure_chunk_size(1024 * gigabyte)
    assert chunk_size_1tb > AZURE_CHUNK_SIZE
    assert math.ceil(1024 * gigabyte / chunk_size_1tb) <= AZURE_MAX_BLOCKS

    # Files above the Azure block-blob ceiling are rejected.
    with pytest.raises(ValueError):
        azure_chunk_size(AZURE_MAX_OBJECT_SIZE + 1)


def test_azure_client_wired_with_scaled_chunk_size():
    """The Azure branch of ``_create_file_transfer_client`` should construct the
    storage client with a chunk size that keeps the number of blocks within the
    Azure 50,000-block-per-blob limit, scaling it up for very large files.
    """
    import math
    from unittest.mock import MagicMock

    from snowflake.connector import SnowflakeConnection
    from snowflake.connector.constants import (
        AZURE_CHUNK_SIZE,
        AZURE_FS,
        AZURE_MAX_BLOCKS,
    )
    from snowflake.connector.file_transfer_agent import (
        SnowflakeFileMeta,
        SnowflakeFileTransferAgent,
        StorageCredential,
    )

    gigabyte = 1024**3

    stage_info = {
        "locationType": "AZURE",
        "location": "container/path",
        "storageAccount": "storageaccount",
        "endPoint": "blob.core.windows.net",
        "creds": {"AZURE_SAS_TOKEN": "sas_token"},
    }
    credentials = StorageCredential(
        stage_info["creds"],
        MagicMock(autospec=SnowflakeConnection),
        "PUT file:///tmp/file @~",
    )

    # Build a bare agent and populate only the attributes the Azure branch reads,
    # so we can exercise the wiring without a live connection or a real upload.
    agent = object.__new__(SnowflakeFileTransferAgent)
    agent._stage_location_type = AZURE_FS
    agent._stage_info = stage_info
    agent._credentials = credentials
    agent._unsafe_file_write = False

    def azure_client_for(file_size: int):
        meta = SnowflakeFileMeta(
            name="big_file",
            src_file_name="big_file",
            stage_location_type=AZURE_FS,
            src_file_size=file_size,
            dst_file_name="big_file",
        )
        return agent._create_file_transfer_client(meta)

    # Normal-sized file: default chunk size, comfortably within the block limit.
    small_client = azure_client_for(1 * gigabyte)
    assert small_client.chunk_size == AZURE_CHUNK_SIZE
    assert math.ceil(1 * gigabyte / small_client.chunk_size) <= AZURE_MAX_BLOCKS

    # Very large file (1 TB): the chunk size scales up so the block count stays
    # within the Azure limit. At the old hardcoded 4 MB this file would have
    # required ~262,000 blocks and failed the upload outright.
    large_file_size = 1024 * gigabyte
    large_client = azure_client_for(large_file_size)
    assert large_client.chunk_size > AZURE_CHUNK_SIZE
    assert math.ceil(large_file_size / large_client.chunk_size) <= AZURE_MAX_BLOCKS
