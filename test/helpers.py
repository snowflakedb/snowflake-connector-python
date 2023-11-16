#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import math
import os
import random
import secrets
import time
from typing import TYPE_CHECKING, Pattern, Sequence
from unittest.mock import Mock

import pytest

from snowflake.connector.compat import OK

if TYPE_CHECKING:
    import snowflake.connector.connection

try:
    from snowflake.connector.arrow_context import ArrowConverterContext
except ImportError:
    pass

try:
    from snowflake.connector.nanoarrow_arrow_iterator import (
        PyArrowRowIterator as NanoarrowPyArrowRowIterator,
    )
    from snowflake.connector.nanoarrow_arrow_iterator import (
        PyArrowTableIterator as NanoarrowPyArrowTableIterator,
    )
except ImportError:
    pass
from snowflake.connector.errors import OperationalError

try:
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


def create_mock_response(status_code: int) -> Mock:
    """Create a Mock "Response" with a given status code. See `test_result_batch.py` for examples.
    Args:
        status_code: the status code of the response.
    Returns:
        A Mock object that can be used as a Mock Response in tests.
    """
    mock_resp = Mock()
    mock_resp.status_code = status_code
    mock_resp.raw = "success" if status_code == OK else "fail"
    return mock_resp


def verify_log_tuple(
    module: str,
    level: int,
    message: str | Pattern,
    log_tuples: Sequence[tuple[str, int, str]],
):
    """Convenience function to be able to search for regex patterns in log messages.

    Designed to search caplog.record_tuples.

    Notes:
        - module could be extended to take a pattern too
    """
    for _module, _level, _message in log_tuples:
        if _module == module and _level == level:
            if _message == message or (
                isinstance(message, Pattern) and message.search(_message)
            ):
                return True
    return False


def _wait_while_query_running(
    con: snowflake.connector.connection.SnowflakeConnection,
    sfqid: str,
    sleep_time: int,
    dont_cache: bool = False,
) -> None:
    """
    Checks if the provided still returns that it is still running, and if so,
    sleeps for the specified time in a while loop.
    """
    query_status = con._get_query_status if dont_cache else con.get_query_status
    while con.is_still_running(query_status(sfqid)):
        time.sleep(sleep_time)


def _wait_until_query_success(
    con: snowflake.connector.connection.SnowflakeConnection,
    sfqid: str,
    num_checks: int,
    sleep_per_check: int,
) -> None:
    for _ in range(num_checks):
        status = con.get_query_status(sfqid)
        if status == QueryStatus.SUCCESS:
            break
        time.sleep(sleep_per_check)
    else:
        pytest.fail(
            "We should have broke out of wait loop for query success."
            f"Query ID: {sfqid}"
            f"Final query status: {status}"
        )


def create_nanoarrow_pyarrow_iterator(input_data, use_table_iterator):
    # create nanoarrow based iterator
    return (
        NanoarrowPyArrowRowIterator(
            None,
            input_data,
            ArrowConverterContext(
                session_parameters={"TIMEZONE": "America/Los_Angeles"}
            ),
            False,
            False,
            False,
        )
        if not use_table_iterator
        else NanoarrowPyArrowTableIterator(
            None,
            input_data,
            ArrowConverterContext(
                session_parameters={"TIMEZONE": "America/Los_Angeles"}
            ),
            False,
            False,
            False,
        )
    )


def _arrow_error_stream_chunk_remove_single_byte_test(use_table_iterator):
    # this test removes single byte from the input bytes
    with open(os.path.join(os.path.dirname(__file__), "data", "test_arrow_data")) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)
    exception_result = []
    result_array = []
    for i in range(len(decode_bytes)):
        try:
            # removing the i-th char in the bytes
            iterator = create_nanoarrow_pyarrow_iterator(
                decode_bytes[:i] + decode_bytes[i + 1 :], use_table_iterator
            )
            for k in iterator:
                result_array.append(k)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                next(iterator)
            assert isinstance(e, OperationalError)
            exception_result.append((i, str(e), e))

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(result_array) == 0


def _arrow_error_stream_chunk_remove_random_length_bytes_test(use_table_iterator):
    # this test removes random bytes from the input bytes
    def remove_bytes(byte_str, num_bytes):
        """Remove a specified number of random bytes from a byte string."""
        if num_bytes >= len(byte_str):
            return (
                bytearray()
            )  # Return an empty bytearray if attempting to remove more bytes than available.

        indices_to_remove = random.sample(range(len(byte_str)), num_bytes)
        new_byte_str = bytearray(
            byte for idx, byte in enumerate(byte_str) if idx not in indices_to_remove
        )
        return new_byte_str

    with open(os.path.join(os.path.dirname(__file__), "data", "test_arrow_data")) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)
    exception_result = []
    result_array = []

    bytes_to_remove_exponent = math.log2(len(decode_bytes))
    for i in range(1, int(bytes_to_remove_exponent)):
        # randomly pick 2, 4, ... 2^stop bytes
        try:
            # removing the i-th char in the bytes
            iterator = create_nanoarrow_pyarrow_iterator(
                bytes(remove_bytes(decode_bytes, 2**i)), use_table_iterator
            )
            for k in iterator:
                result_array.append(k)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                next(iterator)
            exception_result.append((i, str(e), e))
            assert isinstance(e, OperationalError)

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(result_array) == 0


def _arrow_error_stream_random_input_test(use_table_iterator):
    # this test reads randomly generated byte string
    exception_result = []
    result_array = []
    for i in range(23):  # create input bytes array of size 0, 1, 2, ... 2^22
        input_bytes = secrets.token_bytes(2**i)
        try:
            iterator = create_nanoarrow_pyarrow_iterator(
                input_bytes, use_table_iterator
            )
            for k in iterator:
                result_array.append(k)
        except Exception as e:
            with pytest.raises(UnboundLocalError):
                # create_arrow_iterator_method will raise error so
                # iterator is not instantiated at all
                next(iterator)
            assert isinstance(e, OperationalError)
            exception_result.append((i, str(e), e))

    # note: nanoarrow and pyarrow exception information doesn't match, but the python
    # error instance users get should be the same
    assert len(exception_result)
    assert len(result_array) == 0
