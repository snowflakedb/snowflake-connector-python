#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.chunk_downloader import ArrowChunkIterator
from snowflake.connector.compat import PY34_EXACT
from io import BytesIO
import random
import pytest

try:
    from pyarrow import RecordBatchStreamReader
    from pyarrow import RecordBatchStreamWriter
    from pyarrow import RecordBatch
    import pyarrow
except ImportError:
    pass


@pytest.mark.skipif(
    PY34_EXACT,
    reason="Pyarrow is not support in python3.4 envrionment")
def test_iterate_over_single_arrow_chunk():
    stream = BytesIO()
    field_foo = pyarrow.field("column_foo", pyarrow.int64(), True)
    field_bar = pyarrow.field("column_bar", pyarrow.int64(), True)
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
            for k in range(batch_row_count):
                data = None if bool(random.getrandbits(1)) else random.randint(-100, 100)
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
    it = ArrowChunkIterator(reader)

    count = 0
    while True:
        try:
            val = next(it)
            assert val[0].as_py() == expected_data[int(count / 10)][0][count % 10]
            assert val[1].as_py() == expected_data[int(count / 10)][1][count % 10]
            count += 1
        except StopIteration:
            assert count == 100
            break

