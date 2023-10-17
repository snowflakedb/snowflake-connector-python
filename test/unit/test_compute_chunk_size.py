#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

try:
    from snowflake.connector.compute_chunk_size import ChunkSizeCalculator, constants

    expected_chunk_size = constants["CURRENT_CHUNK_SIZE"]
    max_part_size = constants["MAX_PART_SIZE"]
    min_part_size = constants["MIN_PART_SIZE"]
    max_object_size = constants["MAX_OBJECT_SIZE"]
    sample_file_size_2gb = 2 * 1024 * 1024 * 1024
    sample_file_size_85gb = 85 * 1024 * 1024 * 1024
    sample_file_size_5tb = 4.9 * 1024 * 1024 * 1024 * 1024
    sample_file_size_6tb = 6 * 1024 * 1024 * 1024 * 1024
    sample_chunk_size_4mb = 4 * 1024 * 1024
    sample_chunk_size_10mb = 10 * 1024 * 1024
except ImportError:
    pass


pytestmark = pytest.mark.skipolddriver


def test_check_chunk_size():
    chunk_size_calculator = ChunkSizeCalculator()
    chunk_size_1 = chunk_size_calculator.compute_chunk_size(sample_file_size_2gb)
    assert chunk_size_1 == expected_chunk_size
    chunk_size_2 = chunk_size_calculator.compute_chunk_size(sample_file_size_5tb)
    assert chunk_size_2 <= max_part_size

    error_message = f"File size {sample_file_size_6tb} exceeds the maximum file size {max_object_size}."

    with pytest.raises(Exception) as exc:
        chunk_size_calculator.compute_chunk_size(sample_file_size_6tb)
    assert error_message in str(exc)


def test_check_min_chunk_size():
    chunk_size_calculator = ChunkSizeCalculator()
    chunk_size_1 = chunk_size_calculator._check_min_chunk_size(sample_chunk_size_4mb)
    assert chunk_size_1 == min_part_size

    chunk_size_2 = chunk_size_calculator._check_min_chunk_size(sample_chunk_size_10mb)
    assert chunk_size_2 == sample_chunk_size_10mb


def test_check_max_parts():
    chunk_size_calculator = ChunkSizeCalculator()
    chunk_size_3 = chunk_size_calculator._check_max_parts(
        expected_chunk_size, sample_file_size_85gb
    )
    assert chunk_size_3 <= max_part_size
    assert chunk_size_3 >= min_part_size

    chunk_size_4 = chunk_size_calculator._check_max_parts(
        expected_chunk_size, sample_file_size_2gb
    )
    assert chunk_size_4 <= max_part_size
    assert chunk_size_4 >= min_part_size
