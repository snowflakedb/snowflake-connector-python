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
    stream = BytesIO()
    column_meta = [
            { "logicalType" : "TEXT" },
            { "logicalType" : "TEXT" }
    ]
    field_foo = pyarrow.field("column_foo", pyarrow.string(), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.string(), True, column_meta[1])
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
                    data = None if bool(random.getrandbits(1)) else random.randint(-100, 100)
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(str(data))
            column_arrays.append(column_data)
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
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_int64_chunk():
    stream = BytesIO()
    column_meta = [
            { "logicalType" : "FIXED", "precision" : "38", "scale" : "0" },
            { "logicalType" : "FIXED", "precision" : "38", "scale" : "0" }
    ]
    field_foo = pyarrow.field("column_foo", pyarrow.int64(), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.int64(), True, column_meta[1])
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
                    data = None if bool(random.getrandbits(1)) else random.randint(-10000000000, 10000000000)
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
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
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_bool_chunk():
    stream = BytesIO()
    column_meta = [
            { "logicalType" : "BOOLEAN" },
            { "logicalType" : "BOOLEAN" }
    ]
    field_foo = pyarrow.field("column_foo", pyarrow.bool_(), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.bool_(), True, column_meta[1])
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
                    data = None if bool(random.getrandbits(1)) else bool(random.getrandbits(1))
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
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
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_iterate_over_float_chunk():
    stream = BytesIO()
    column_meta = [
            { "logicalType" : "REAL" },
            { "logicalType" : "FLOAT" }
    ]
    field_foo = pyarrow.field("column_foo", pyarrow.float64(), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.float64(), True, column_meta[1])
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
                    data = None if bool(random.getrandbits(1)) else random.uniform(-100.0, 100.0)
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
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
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break


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
    stream = BytesIO()
    column_meta = {
        "byteLength" : "4",
        "logicalType" : "DATE",
        "precision" : "38",
        "scale" : "0",
        "charLength" : "0"
    }

    field_foo = pyarrow.field("column_foo", pyarrow.date32(), True, column_meta)
    field_bar = pyarrow.field("column_bar", pyarrow.date32(), True, column_meta)
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
                    data = None if bool(random.getrandbits(1)) else datetime.date.fromordinal(random.randint(1, 1000000))
                    if data != None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
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
            assert val[1] == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break
