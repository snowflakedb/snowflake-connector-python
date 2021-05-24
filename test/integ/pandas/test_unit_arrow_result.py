#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import datetime
import math
import random
from io import BytesIO

import pytest

from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.cursor import SnowflakeCursor

try:
    from snowflake.connector.options import installed_pandas  # NOQA
except ImportError:
    installed_pandas = False

try:
    import pyarrow
    from pyarrow import RecordBatch  # NOQA
    from pyarrow import RecordBatchStreamReader  # NOQA
    from pyarrow import RecordBatchStreamWriter  # NOQA
except ImportError:
    pass

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator  # NOQA
    from snowflake.connector.arrow_result import ArrowResult  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

EPSILON = 1e-8


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.",
)
def test_fdb_result_data_empty_row_fetch():
    raw_response = {
        "rowsetBase64": "",
        "rowtype": [{"name": "c1"}, {"name": "c2"}],
        "chunks": ["f1", "f2", "f3"],
    }

    random.seed(datetime.datetime.now())
    column_meta = [
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
    ]

    def int64_generator():
        return random.randint(-9223372036854775808, 9223372036854775807)

    chunk_count = 3
    expected_chunk_result = chunk_count * [None]
    arrow_stream = chunk_count * [None]
    batch_row_count = 10
    batch_count = 9

    for i in range(chunk_count):
        arrow_stream[i], expected_chunk_result[i] = generate_data(
            [pyarrow.int64(), pyarrow.int64()],
            column_meta,
            int64_generator,
            batch_count,
            batch_row_count,
        )

    con = MockConnection()
    cur = MockCursor(con)
    res = ArrowResult(
        raw_response,
        cur,
        use_dict_result=False,
        _chunk_downloader=MockDownloader(arrow_stream),
    )
    cur._query_result_format = "arrow"
    cur._result = res

    count = 0
    while True:
        try:
            data = res.__next__()

            expected_chunk, expected_row_index_in_chunk = divmod(
                count, batch_row_count * batch_count
            )
            expected_batch_index, expected_row_index_in_batch = divmod(
                expected_row_index_in_chunk, batch_row_count
            )

            assert (
                data[0]
                == expected_chunk_result[expected_chunk][expected_batch_index][0][
                    expected_row_index_in_batch
                ]
            )
            assert (
                data[1]
                == expected_chunk_result[expected_chunk][expected_batch_index][1][
                    expected_row_index_in_batch
                ]
            )

            count += 1

        except StopIteration:
            break

    assert count == chunk_count * batch_row_count * batch_count


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or missing pandas.",
)
def test_fdb_result_data_empty_pandas_fetch_all():
    raw_response = {
        "rowsetBase64": "",
        "rowtype": [{"name": "c1"}, {"name": "c2"}],
        "chunks": ["f1", "f2", "f3"],
    }

    random.seed(datetime.datetime.now())
    column_meta = [
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
    ]

    def int64_generator():
        return random.randint(-9223372036854775, 9223372036854775)

    chunk_count = 3
    expected_chunk_result = chunk_count * [None]
    arrow_stream = chunk_count * [None]
    batch_row_count = 10
    batch_count = 9

    for i in range(chunk_count):
        arrow_stream[i], expected_chunk_result[i] = generate_data(
            [pyarrow.int64(), pyarrow.int64()],
            column_meta,
            int64_generator,
            batch_count,
            batch_row_count,
        )

    con = MockConnection()
    cur = MockCursor(con)
    res = ArrowResult(
        raw_response,
        cur,
        use_dict_result=False,
        _chunk_downloader=MockDownloader(arrow_stream),
    )
    cur._query_result_format = "arrow"
    cur._result = res

    df = res._fetch_pandas_all()

    # assert row count
    assert df.shape[0] == batch_row_count * batch_count * chunk_count
    # assert column count
    assert df.shape[1] == 2

    for i in range(2):
        col = df.iloc[:, i]

        for idx, val in col.items():
            expected_chunk, expected_row_index_in_chunk = divmod(
                idx, batch_row_count * batch_count
            )
            expected_batch_index, expected_row_index_in_batch = divmod(
                expected_row_index_in_chunk, batch_row_count
            )

            expected_val = expected_chunk_result[expected_chunk][expected_batch_index][
                i
            ][expected_row_index_in_batch]

            if math.isnan(val):
                assert expected_val is None
            else:
                assert abs(expected_val - val) < EPSILON


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_fdb_result_data_empty_pandas_fetch_by_batch():
    raw_response = {
        "rowsetBase64": "",
        "rowtype": [{"name": "c1"}, {"name": "c2"}],
        "chunks": ["f1", "f2", "f3"],
    }

    random.seed(datetime.datetime.now())
    column_meta = [
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
        {"logicalType": "FIXED", "precision": "38", "scale": "0"},
    ]

    def int64_generator():
        return random.randint(-9223372036854775, 9223372036854775)

    chunk_count = 3
    expected_chunk_result = chunk_count * [None]
    arrow_stream = chunk_count * [None]
    batch_row_count = 10
    batch_count = 9

    for i in range(chunk_count):
        arrow_stream[i], expected_chunk_result[i] = generate_data(
            [pyarrow.int64(), pyarrow.int64()],
            column_meta,
            int64_generator,
            batch_count,
            batch_row_count,
        )
    con = MockConnection()
    cur = MockCursor(con)
    res = ArrowResult(
        raw_response,
        cur,
        use_dict_result=False,
        _chunk_downloader=MockDownloader(arrow_stream),
    )
    cur._query_result_format = "arrow"
    cur._result = res

    chunk_index = 0
    for df in cur.fetch_pandas_batches():
        # assert row count
        assert df.shape[0] == batch_row_count * batch_count
        # assert column count
        assert df.shape[1] == 2

        for i in range(2):
            col = df.iloc[:, i]

            for idx, val in col.items():
                expected_batch_index, expected_row_index_in_batch = divmod(
                    idx, batch_row_count
                )

                expected_val = expected_chunk_result[chunk_index][expected_batch_index][
                    i
                ][expected_row_index_in_batch]

                if math.isnan(val):
                    assert expected_val is None
                else:
                    assert abs(expected_val - val) < EPSILON

        chunk_index += 1


class MockConnection:
    def __init__(self):
        self._log_max_query_length = 20
        self._numpy = False

    @property
    def log_max_query_length(self):
        return self._log_max_query_length


class MockCursor(SnowflakeCursor):
    def __init__(self, connection):
        SnowflakeCursor.__init__(self, connection)
        self._first_chunk_time = None

    def _log_telemetry_job_data(self, telemetry_field, value):
        pass


class MockDownloader:
    def __init__(self, chunk_stream):
        self._arrow_stream = []
        self._current_chunk_index = -1
        self._arrow_stream = chunk_stream
        self._total_millis_downloading_chunks = None
        self._total_millis_parsing_chunks = None

    def next_chunk(self):
        self._current_chunk_index += 1
        return MockChunk(self._arrow_stream[self._current_chunk_index])

    def terminate(self):
        pass


class MockChunk:
    def __init__(self, data):
        session_parameters = {"TIMEZONE": "America/Los_Angeles"}
        self.result_data = PyArrowIterator(
            None, data, ArrowConverterContext(session_parameters), False, False
        )


def generate_data(
    pyarrow_type, column_meta, source_data_generator, batch_count, batch_row_count
):
    stream = BytesIO()

    assert len(pyarrow_type) == len(column_meta)

    column_size = len(pyarrow_type)
    fields = []
    for i in range(column_size):
        fields.append(
            pyarrow.field("column_{}".format(i), pyarrow_type[i], True, column_meta[i])
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

        expected_data.append(column_arrays)

        column_names = ["column_{}".format(i) for i in range(column_size)]
        rb = RecordBatch.from_arrays(py_arrays, column_names)
        writer.write_batch(rb)

    writer.close()

    # seek stream to begnning so that we can read from stream
    stream.seek(0)

    return stream, expected_data
