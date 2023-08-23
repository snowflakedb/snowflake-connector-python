#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import base64
import io
import os.path

from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.arrow_iterator import PyArrowIterator
from snowflake.connector.version import VERSION


def create_pyarrow_iterator(input_data):
    # create nanoarrow based iterator
    return PyArrowIterator(
        None,
        input_data,
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
    )


def create_old_pyarrow_iterator(input_data):
    # created vendored arrow based iterator
    return PyArrowIterator(
        None,
        io.BytesIO(input_data),
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
    )


create_arrow_iterator_method = (
    create_old_pyarrow_iterator
    if str(VERSION[2]).isdigit()
    else create_pyarrow_iterator
)


def test_connector_error_base64_stream():
    with open(os.path.join(os.path.dirname(__file__), "test_arrow_data")) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)
    last_exc = None
    result = []
    succeeded_result = []
    # stop pos, change it to stop at different pos to observe different error code/seg fault
    stop = len(decode_bytes) - 1
    for i in range(0, stop):
        try:
            # removing the i-th char in the bytes
            for _ in create_arrow_iterator_method(
                decode_bytes[:i] + decode_bytes[i + 1 :]
            ):
                pass
            succeeded_result.append(i)
        except Exception as e:
            if str(e) != last_exc:
                result.append((i, str(e)))
                last_exc = str(e)

    for k, v in result:
        print(k, v)


"""
vendored arrow error cases:

0 255005: 255005: Failed to open arrow stream: b'Invalid IPC stream: negative continuation token'
4 255005: 255005: Failed to open arrow stream: b'Expected to read 268435500 metadata bytes, but only read 32943'
5 255005: 255005: Failed to open arrow stream: b'Expected to read 268435680 metadata bytes, but only read 32943'
6 255005: 255005: Failed to open arrow stream: b'Expected to read 268446944 metadata bytes, but only read 32943'
8 255005: 255005: Failed to open arrow stream: b'Invalid flatbuffers message.'
9 255005: 255005: Failed to open arrow stream: b'Old metadata version not supported'
25 255005: 255005: Failed to open arrow stream: b'Invalid flatbuffers message.'
11484 255005: 255005: Failed to open arrow stream: b'Integers with less than 8 bits not implemented'
11496 255005: 255005: Failed to read next arrow batch: b'Invalid IPC stream: negative continuation token'
11500 255005: 255005: Failed to read next arrow batch: b'Expected to read 335544327 metadata bytes, but only read 21447'
11501 255005: 255005: Failed to read next arrow batch: b'Expected to read 335544472 metadata bytes, but only read 21447'
11502 255005: 255005: Failed to read next arrow batch: b'Expected to read 335546264 metadata bytes, but only read 21447'
11504 255005: 255005: Failed to read next arrow batch: b'Invalid flatbuffers message.'
11505 255005: 255005: Failed to read next arrow batch: b'Old metadata version not supported'
11525 255005: 255005: Failed to read next arrow batch: b'Invalid flatbuffers message.'
12840 255005: 255005: Failed to read next arrow batch: b'Expected to be able to read 19504 bytes for message body, got 19503'

"""
