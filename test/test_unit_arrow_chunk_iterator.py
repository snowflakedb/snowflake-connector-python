#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from io import BytesIO
import random
import pytest
import decimal
import datetime
import os

try:
    from pyarrow import RecordBatchStreamReader
    from pyarrow import RecordBatchStreamWriter
    from pyarrow import RecordBatch
    import pyarrow
except ImportError as e:
    pass

try:
    from snowflake.connector.arrow_iterator import PyArrowChunkIterator
    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_string_chunk():
    column_meta = [
            {"logicalType": "TEXT"},
            {"logicalType": "TEXT"}
    ]

    def str_generator():
        return str(random.randint(-100, 100))

    iterate_over_test_chunk([pyarrow.string(), pyarrow.string()],
                            column_meta,  str_generator)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_int64_chunk():
    column_meta = [
            {"logicalType": "FIXED", "precision": "38", "scale": "0"},
            {"logicalType": "FIXED", "precision": "38", "scale": "0"}
    ]

    def int64_generator():
        return random.randint(-10000000000, 10000000000)

    iterate_over_test_chunk([pyarrow.int64(), pyarrow.int64()],
                            column_meta, int64_generator)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_bool_chunk():
    column_meta = {"logicalType": "BOOLEAN"}

    def bool_generator():
        return bool(random.getrandbits(1))

    iterate_over_test_chunk([pyarrow.bool_(), pyarrow.bool_()],
                            [column_meta, column_meta],
                            bool_generator)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_float_chunk():
    column_meta = [
            {"logicalType": "REAL"},
            {"logicalType": "FLOAT"}
    ]

    def float_generator():
        return random.uniform(-100.0, 100.0)

    iterate_over_test_chunk([pyarrow.float64(), pyarrow.float64()],
                            column_meta, float_generator)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_decimal_chunk():
    # TODO: to add more test case to cover as much code as possible
    #       e.g. Decimal(19, 0) for Int64, Decimal(9, 0) for Int32, Decimal(4, 0) for Int16, Decimal(2, 0) for Int8

    def get_random_decimal(precision, scale):
        data = []
        for i in range(precision):
            data.append(str(random.randint(1,9)))

        if scale:
            data.insert(-scale, '.')
        return decimal.Decimal("".join(data))

    stream = BytesIO()
    column_meta = [
            { "logicalType" : "FIXED", "precision" : "10", "scale" : "3" },
            { "logicalType" : "FIXED", "precision" : "38", "scale" : "0" }
    ]
    field_foo = pyarrow.field("column_foo", pyarrow.decimal128(10, 3), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.decimal128(38, 0), True, column_meta[1])
    schema = pyarrow.schema([field_foo, field_bar])

    column_size = 2
    batch_row_count = 10
    batch_count = 10
    expected_data = []
    writer = RecordBatchStreamWriter(stream, schema)

    for i in range(batch_count):
        column_arrays = []
        py_arrays = []
        for j in range(column_size):
            column_data = []
            not_none_cnt = 0
            while not_none_cnt == 0:
                column_data.clear()
                for k in range(batch_row_count):
                    data = None if bool(random.getrandbits(1)) else get_random_decimal(10 if j % 2 == 0 else 38, 3 if j % 2 == 0 else 0)
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data if j % 2 == 0 else [int(data) if data is not None else None for data in column_data])
            py_arrays.append(pyarrow.array(column_data))

        expected_data.append(column_arrays)
        rb = RecordBatch.from_arrays(py_arrays, ["column_foo", "column_bar"])
        writer.write_batch(rb)

    writer.close()

    # seek stream to begnning so that we can read from stream
    stream.seek(0)
    reader = RecordBatchStreamReader(stream)
    it = PyArrowChunkIterator(reader)

    count = 0
    while True:
        try:
            val = next(it)
            assert val[0] == expected_data[int(count / 10)][0][count % 10]
            assert type(val[0]) == type(expected_data[int(count / 10)][0][count % 10])  # Decimal type or NoneType
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            assert type(val[1]) == type(expected_data[int(count / 10)][1][count % 10])  # Int type or NoneType
            count += 1
        except StopIteration:
            assert count == 100
            break


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_date_chunk():
    column_meta = {
        "byteLength": "4",
        "logicalType": "DATE",
        "precision": "38",
        "scale": "0",
        "charLength": "0"
    }

    def date_generator():
        return datetime.date.fromordinal(random.randint(1, 1000000))

    iterate_over_test_chunk([pyarrow.date32(), pyarrow.date32()],
                            [column_meta, column_meta],
                            date_generator)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_binary_chunk():
    column_meta = {
        "byteLength": "100",
        "logicalType": "BINARY",
        "precision": "0",
        "scale": "0",
        "charLength": "0"
    }

    def byte_array_generator():
        return bytearray(os.urandom(1000))

    iterate_over_test_chunk([pyarrow.binary(), pyarrow.binary()],
                            [column_meta, column_meta],
                            byte_array_generator)


def iterate_over_test_chunk(pyarrow_type, column_meta, source_data_generator):
    stream = BytesIO()

    assert len(pyarrow_type) == len(column_meta)

    column_size = len(pyarrow_type)
    batch_row_count = 10
    batch_count = 9

    fields = []
    for i in range(column_size):
        fields.append(pyarrow.field("column_{}".format(i), pyarrow_type[i], True, column_meta[i]))
    schema = pyarrow.schema(fields)

    expected_data = []
    writer = RecordBatchStreamWriter(stream, schema)

    for i in range(batch_count):
        column_arrays = []
        py_arrays = []
        for j in range(column_size):
            column_data = []
            not_none_cnt = 0
            while not_none_cnt == 0:
                column_data.clear()
                for k in range(batch_row_count):
                    data = None if bool(random.getrandbits(1)) else source_data_generator()
                    if data:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
            py_arrays.append(pyarrow.array(column_data))

        expected_data.append(column_arrays)

        column_names = ["column_{}".format(i) for i in range(column_size)]
        rb = RecordBatch.from_arrays(py_arrays, column_names)
        writer.write_batch(rb)

    writer.close()

    # seek stream to begnning so that we can read from stream
    stream.seek(0)
    reader = RecordBatchStreamReader(stream)
    it = PyArrowChunkIterator(reader)

    count = 0
    while True:
        try:
            val = next(it)
            for i in range(column_size):
                batch_index = int(count / batch_row_count)
                assert val[i] == expected_data[batch_index][i][count - batch_row_count * batch_index]
            count += 1
        except StopIteration:
            assert count == (batch_count * batch_row_count)
            break
