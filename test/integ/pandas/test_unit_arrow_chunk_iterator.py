#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import datetime
import decimal
import os
import random
from io import BytesIO

import pytest
import pytz

from snowflake.connector.arrow_context import ArrowConverterContext

try:
    from snowflake.connector.options import installed_pandas
except ImportError:
    installed_pandas = False

try:
    import tzlocal
except ImportError:
    tzlocal = None

try:
    import pyarrow
    from pyarrow import RecordBatchStreamReader  # NOQA
    from pyarrow import RecordBatch, RecordBatchStreamWriter
except ImportError:
    pass

try:
    from snowflake.connector.nanoarrow_arrow_iterator import (
        PyArrowRowIterator as NanoarrowPyArrowRowIterator,
    )

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_string_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [{"logicalType": "TEXT"}, {"logicalType": "TEXT"}]
    field_foo = pyarrow.field("column_foo", pyarrow.string(), True, column_meta[0])
    field_bar = pyarrow.field("column_bar", pyarrow.string(), True, column_meta[1])
    pyarrow.schema([field_foo, field_bar])

    def str_generator():
        return str(random.randint(-100, 100))

    iterate_over_test_chunk(
        [pyarrow.string(), pyarrow.string()],
        column_meta,
        str_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_int64_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
    ]

    def int64_generator():
        return random.randint(-9223372036854775808, 9223372036854775807)

    iterate_over_test_chunk(
        [pyarrow.int64(), pyarrow.int64()],
        column_meta,
        int64_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_int32_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [
        {"logicalType": "FIXED", "precision": "10", "scale": "0"},
        {"logicalType": "FIXED", "precision": "10", "scale": "0"},
    ]

    def int32_generator():
        return random.randint(-2147483648, 2147483637)

    iterate_over_test_chunk(
        [pyarrow.int32(), pyarrow.int32()],
        column_meta,
        int32_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_int16_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [
        {"logicalType": "FIXED", "precision": "5", "scale": "0"},
        {"logicalType": "FIXED", "precision": "5", "scale": "0"},
    ]

    def int16_generator():
        return random.randint(-32768, 32767)

    iterate_over_test_chunk(
        [pyarrow.int16(), pyarrow.int16()],
        column_meta,
        int16_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_int8_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [
        {"logicalType": "FIXED", "precision": "3", "scale": "0"},
        {"logicalType": "FIXED", "precision": "3", "scale": "0"},
    ]

    def int8_generator():
        return random.randint(-128, 127)

    iterate_over_test_chunk(
        [pyarrow.int8(), pyarrow.int8()],
        column_meta,
        int8_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_bool_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = {"logicalType": "BOOLEAN"}

    def bool_generator():
        return bool(random.getrandbits(1))

    iterate_over_test_chunk(
        [pyarrow.bool_(), pyarrow.bool_()],
        [column_meta, column_meta],
        bool_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_float_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = [{"logicalType": "REAL"}, {"logicalType": "FLOAT"}]

    def float_generator():
        return random.uniform(-100.0, 100.0)

    iterate_over_test_chunk(
        [pyarrow.float64(), pyarrow.float64()],
        column_meta,
        float_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_decimal_chunk():
    random.seed(datetime.datetime.now().timestamp())
    precision = random.randint(1, 38)
    scale = random.randint(0, precision)
    datatype = None
    if precision <= 2:
        datatype = pyarrow.int8()
    elif precision <= 4:
        datatype = pyarrow.int16()
    elif precision <= 9:
        datatype = pyarrow.int32()
    elif precision <= 19:
        datatype = pyarrow.int64()
    else:
        datatype = pyarrow.decimal128(precision, scale)

    def decimal_generator(_precision, _scale):
        def decimal128_generator(precision, scale):
            data = []
            for _ in range(precision):
                data.append(str(random.randint(0, 9)))

            if scale:
                data.insert(-scale, ".")
            return decimal.Decimal("".join(data))

        def int64_generator(precision):
            data = random.randint(-9223372036854775808, 9223372036854775807)
            return int(str(data)[: precision if data >= 0 else precision + 1])

        def int32_generator(precision):
            data = random.randint(-2147483648, 2147483637)
            return int(str(data)[: precision if data >= 0 else precision + 1])

        def int16_generator(precision):
            data = random.randint(-32768, 32767)
            return int(str(data)[: precision if data >= 0 else precision + 1])

        def int8_generator(precision):
            data = random.randint(-128, 127)
            return int(str(data)[: precision if data >= 0 else precision + 1])

        if _precision <= 2:
            return int8_generator(_precision)
        elif _precision <= 4:
            return int16_generator(_precision)
        elif _precision <= 9:
            return int32_generator(_precision)
        elif _precision <= 19:
            return int64_generator(_precision)
        else:
            return decimal128_generator(_precision, _scale)

    def expected_data_transform_decimal(_precision, _scale):
        def expected_data_transform_decimal_impl(
            data, precision=_precision, scale=_scale
        ):
            if precision <= 19:
                return decimal.Decimal(data).scaleb(-scale)
            else:
                return data

        return expected_data_transform_decimal_impl

    column_meta = {
        "logicalType": "FIXED",
        "precision": str(precision),
        "scale": str(scale),
    }
    iterate_over_test_chunk(
        [datatype, datatype],
        [column_meta, column_meta],
        lambda: decimal_generator(precision, scale),
        expected_data_transform_decimal(precision, scale),
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_date_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = {
        "byteLength": "4",
        "logicalType": "DATE",
        "precision": "38",
        "scale": "0",
        "charLength": "0",
    }

    def date_generator():
        return datetime.date.fromordinal(random.randint(1, 1000000))

    iterate_over_test_chunk(
        [pyarrow.date32(), pyarrow.date32()],
        [column_meta, column_meta],
        date_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_binary_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta = {
        "byteLength": "100",
        "logicalType": "BINARY",
        "precision": "0",
        "scale": "0",
        "charLength": "0",
    }

    def byte_array_generator():
        return bytearray(os.urandom(1000))

    iterate_over_test_chunk(
        [pyarrow.binary(), pyarrow.binary()],
        [column_meta, column_meta],
        byte_array_generator,
    )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas option is not installed.",
)
def test_iterate_over_time_chunk():
    random.seed(datetime.datetime.now().timestamp())
    column_meta_int64 = [
        {"logicalType": "TIME", "scale": "9"},
        {"logicalType": "TIME", "scale": "9"},
    ]

    column_meta_int32 = [
        {"logicalType": "TIME", "scale": "4"},
        {"logicalType": "TIME", "scale": "4"},
    ]

    def time_generator_int64():
        return random.randint(0, 86399999999999)

    def time_generator_int32():
        return random.randint(0, 863999999)

    def expected_data_transform_int64(data):
        milisec = data % (10**9)
        milisec //= 10**3
        data //= 10**9
        second = data % 60
        data //= 60
        minute = data % 60
        hour = data // 60
        return datetime.time(hour, minute, second, milisec)

    def expected_data_transform_int32(data):
        milisec = data % (10**4)
        milisec *= 10**2
        data //= 10**4
        second = data % 60
        data //= 60
        minute = data % 60
        hour = data // 60
        return datetime.time(hour, minute, second, milisec)

    iterate_over_test_chunk(
        [pyarrow.int64(), pyarrow.int64()],
        column_meta_int64,
        time_generator_int64,
        expected_data_transform_int64,
    )

    iterate_over_test_chunk(
        [pyarrow.int32(), pyarrow.int32()],
        column_meta_int32,
        time_generator_int32,
        expected_data_transform_int32,
    )


def iterate_over_test_chunk(
    pyarrow_type,
    column_meta,
    source_data_generator,
    expected_data_transformer=None,
):
    stream = BytesIO()

    assert len(pyarrow_type) == len(column_meta)

    column_size = len(pyarrow_type)
    batch_row_count = 10
    batch_count = 9

    fields = []
    for i in range(column_size):
        fields.append(
            pyarrow.field(f"column_{i}", pyarrow_type[i], True, column_meta[i])
        )
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
                column_data = []
                for _ in range(batch_row_count):
                    data = (
                        None if bool(random.getrandbits(1)) else source_data_generator()
                    )
                    if data is not None:
                        not_none_cnt += 1
                    column_data.append(data)
            column_arrays.append(column_data)
            py_arrays.append(pyarrow.array(column_data, type=pyarrow_type[j]))

        if expected_data_transformer:
            for i in range(len(column_arrays)):
                column_arrays[i] = [
                    expected_data_transformer(_data) if _data is not None else None
                    for _data in column_arrays[i]
                ]
        expected_data.append(column_arrays)

        column_names = [f"column_{i}" for i in range(column_size)]
        rb = RecordBatch.from_arrays(py_arrays, column_names)
        writer.write_batch(rb)

    writer.close()

    # seek stream to begnning so that we can read from stream
    stream.seek(0)
    context = ArrowConverterContext()

    it = NanoarrowPyArrowRowIterator(None, stream.read(), context, False, False, False)

    count = 0
    while True:
        try:
            val = next(it)
            for i in range(column_size):
                batch_index = int(count / batch_row_count)
                assert (
                    val[i]
                    == expected_data[batch_index][i][
                        count - batch_row_count * batch_index
                    ]
                )
            count += 1
        except StopIteration:
            assert count == (batch_count * batch_row_count)
            break


def get_timezone(timezone=None):
    """Gets, or uses the session timezone or use the local computer's timezone."""
    try:
        tz = "UTC" if not timezone else timezone
        return pytz.timezone(tz)
    except pytz.exceptions.UnknownTimeZoneError:
        if tzlocal is not None:
            return tzlocal.get_localzone()
        else:
            try:
                return datetime.datetime.timezone.utc
            except AttributeError:
                return pytz.timezone("UTC")
