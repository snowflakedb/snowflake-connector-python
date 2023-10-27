#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

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
        f"File size {sample_file_size_6tb} exceeds the maximum file size {S3_MAX_OBJECT_SIZE} allowed in S3."
        in str(exc)
    )

    chunk_size_1 = _chunk_size_calculator(sample_chunk_size_4mb)
    assert chunk_size_1 >= S3_MIN_PART_SIZE
