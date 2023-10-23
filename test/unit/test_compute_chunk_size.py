#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

try:
    from snowflake.connector.compute_chunk_size import chunk_size_calculator

    expected_chunk_size = 8 * 1024**2
    max_part_size = 5 * 1024**3
    min_part_size = 5 * 1024**2
    max_object_size = 5 * 1024**4
    sample_file_size_2gb = 2 * 1024**3
    sample_file_size_under_5tb = 4.9 * 1024**4
    sample_file_size_6tb = 6 * 1024**4
    sample_chunk_size_4mb = 4 * 1024**2
except ImportError:
    pass


pytestmark = pytest.mark.skipolddriver


def test_check_chunk_size():
    chunk_size_1 = chunk_size_calculator(sample_file_size_2gb)
    assert chunk_size_1 == expected_chunk_size

    chunk_size_2 = chunk_size_calculator(int(sample_file_size_under_5tb))
    assert chunk_size_2 <= max_part_size

    error_message = f"File size {sample_file_size_6tb} exceeds the maximum file size {max_object_size}."

    with pytest.raises(Exception) as exc:
        chunk_size_calculator(sample_file_size_6tb)
    assert error_message in str(exc)

    chunk_size_1 = chunk_size_calculator(sample_chunk_size_4mb)
    assert chunk_size_1 == min_part_size
