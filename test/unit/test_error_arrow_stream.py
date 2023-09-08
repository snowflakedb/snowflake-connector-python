#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import base64
import io
import math
import os.path
import random
import secrets

import pytest

from snowflake.connector.arrow_context import ArrowConverterContext

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator
except ImportError:
    pass
from snowflake.connector.errors import OperationalError
from snowflake.connector.version import VERSION


def create_pyarrow_iterator(input_data, use_table_iterator):
    # create nanoarrow based iterator
    return PyArrowIterator(
        None,
        input_data,
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
        use_table_iterator,
    )


def create_old_pyarrow_iterator(input_data, use_table_iterator):
    # created vendored arrow based iterator
    iterator = PyArrowIterator(
        None,
        io.BytesIO(input_data),
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
    )
    if use_table_iterator:
        iterator.init_table_unit()


create_arrow_iterator_method = (
    create_old_pyarrow_iterator
    if str(VERSION[2]).isdigit()
    else create_pyarrow_iterator
)


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_table_iterator", [False, True])
def test_connector_error_base64_stream_chunk_remove_single_byte(use_table_iterator):
    # this test removes single byte from the input bytes
    with open(os.path.join(os.path.dirname(__file__), "test_arrow_data")) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)
    exception_result = []
    succeeded_result = []
    result_array = []
    for i in range(len(decode_bytes)):
        try:
            # removing the i-th char in the bytes
            iterator = create_arrow_iterator_method(
                decode_bytes[:i] + decode_bytes[i + 1 :], use_table_iterator
            )
            for k in iterator:
                result_array.append(k)
            succeeded_result.append(i)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                for _ in iterator:
                    pass
            assert isinstance(e, OperationalError)
            exception_result.append((i, str(e), e))

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(succeeded_result) == len(result_array) == 0


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_table_iterator", [False, True])
def test_connector_error_base64_stream_chunk_remove_random_length_bytes(
    use_table_iterator,
):
    # this test removes random bytes from the input bytes
    def remove_bytes(byte_str, num_bytes):
        """
        Remove a specified number of random bytes from a byte string.
        """
        if num_bytes >= len(byte_str):
            return (
                bytearray()
            )  # Return an empty bytearray if attempting to remove more bytes than available.

        indices_to_remove = random.sample(range(len(byte_str)), num_bytes)
        new_byte_str = bytearray(
            byte for idx, byte in enumerate(byte_str) if idx not in indices_to_remove
        )
        return new_byte_str

    with open(os.path.join(os.path.dirname(__file__), "test_arrow_data")) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)
    exception_result = []
    succeeded_result = []
    result_array = []

    bytes_to_remove_exponent = math.log2(len(decode_bytes))
    for i in range(1, int(bytes_to_remove_exponent)):
        # randomly pick 2, 4, ... 2^stop bytes
        try:
            # removing the i-th char in the bytes
            iterator = create_arrow_iterator_method(
                bytes(remove_bytes(decode_bytes, 2**i)), use_table_iterator
            )
            for k in iterator:
                result_array.append(k)
            succeeded_result.append(i)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                for _ in iterator:
                    pass
            exception_result.append((i, str(e), e))
            assert isinstance(e, OperationalError)

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(succeeded_result) == len(result_array) == 0


@pytest.mark.skipolddriver
@pytest.mark.parametrize("use_table_iterator", [False, True])
def test_connector_error_random_input(use_table_iterator):
    # this test reads randomly generated byte string
    exception_result = []
    succeeded_result = []
    result_array = []
    for i in range(23):  # create input bytes array of size 0, 1, 2, ... 2^22
        input_bytes = secrets.token_bytes(2**i)
        try:
            iterator = create_arrow_iterator_method(input_bytes, use_table_iterator)
            for k in iterator:
                result_array.append(k)
            succeeded_result.append(i)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                # create_arrow_iterator_method will raise error so
                # iterator is not instantiated at all
                for _ in iterator:
                    pass
            assert isinstance(e, OperationalError)
            exception_result.append((i, str(e), e))

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(succeeded_result) == len(result_array) == 0
