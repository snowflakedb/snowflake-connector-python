#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

from ...helpers import (
    _arrow_error_stream_chunk_remove_random_length_bytes_test,
    _arrow_error_stream_chunk_remove_single_byte_test,
    _arrow_error_stream_random_input_test,
)

pytestmark = pytest.mark.skipolddriver


def test_connector_error_base64_stream_chunk_remove_single_byte():
    _arrow_error_stream_chunk_remove_single_byte_test(use_table_iterator=True)


def test_connector_error_base64_stream_chunk_remove_random_length_bytes():
    _arrow_error_stream_chunk_remove_random_length_bytes_test(use_table_iterator=True)


def test_connector_error_random_input():
    _arrow_error_stream_random_input_test(use_table_iterator=True)
