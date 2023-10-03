#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

from ...helpers import (
    _arrow_error_stream_chunk_remove_random_length_bytes_test,
    _arrow_error_stream_chunk_remove_single_byte_test,
    _arrow_error_stream_random_input_test,
)


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_nanoarrow_iterator", [True])
def test_connector_error_base64_stream_chunk_remove_single_byte(use_nanoarrow_iterator):
    _arrow_error_stream_chunk_remove_single_byte_test(
        use_table_iterator=True, use_nanoarrow_iterator=use_nanoarrow_iterator
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_nanoarrow_iterator", [True, False])
def test_connector_error_base64_stream_chunk_remove_random_length_bytes(
    use_nanoarrow_iterator,
):
    _arrow_error_stream_chunk_remove_random_length_bytes_test(
        use_table_iterator=True, use_nanoarrow_iterator=use_nanoarrow_iterator
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_nanoarrow_iterator", [True, False])
def test_connector_error_random_input(use_nanoarrow_iterator):
    _arrow_error_stream_random_input_test(
        use_table_iterator=True, use_nanoarrow_iterator=use_nanoarrow_iterator
    )
