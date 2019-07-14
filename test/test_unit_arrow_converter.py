#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import pytest
import random
import string

try:
    from pyarrow import RecordBatch
    import pyarrow
    from snowflake.connector.arrow_iterator import FixedColumnConverter
    from snowflake.connector.arrow_iterator import ColumnConverter
except ImportError:
    pass


@pytest.mark.skip(
    reason="Cython is not enabled in build env")
def test_convert_from_fixed():

    column_foo = ("foo", "FIXED", None, None, 1000, 0, True)
    expected_val = []
    array_len = 1000

    for i in range(0, array_len):
        data = None if bool(random.getrandbits(1)) else random.randint(-1000, 1000)
        expected_val.append(data)

    rb = RecordBatch.from_arrays([pyarrow.array(expected_val)], ['column_foo'])

    for col_array in rb:
        converter = FixedColumnConverter(col_array, column_foo)
        for i in range(0, array_len):
            py_val = converter.to_python_native(i)
            assert py_val == expected_val[i]


@pytest.mark.skip(
    reason="Cython is not enabled in build env")
def test_convert_from_binary():

    column_foo = ("foo", "TEXT", None, None, 1000, 0, True)
    column_bar = ("bar", "BINARY", None, None, 1000, 0, True)
    column_metas = [column_foo, column_bar]

    expected_val = []
    array_len = 1000

    string_val = []
    for i in range(0, array_len):
        data = None if bool(random.getrandbits(1)) else generate_random_string()
        string_val.append(data)
    expected_val.append(string_val)

    binary_val = []
    for i in range(0, array_len):
        data = None if bool(random.getrandbits(1)) else generate_random_string().encode('utf-8')
        binary_val.append(data)
    expected_val.append(string_val)

    rb = RecordBatch.from_arrays([pyarrow.array(expected_val[0]),
                                  pyarrow.array(expected_val[1])],
                                 ['col_foo', 'col_bar'])

    for i, col_array in enumerate(rb):
        converter = ColumnConverter(col_array, column_metas[i])
        for j in range(0, array_len):
            py_val = converter.to_python_native(j)
            assert py_val == expected_val[i][j]


def generate_random_string():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(0, 32)])
