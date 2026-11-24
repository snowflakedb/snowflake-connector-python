from __future__ import annotations

import calendar
from datetime import datetime, timezone
from io import BytesIO

import pytest

try:
    import pyarrow
    from pyarrow import RecordBatch, RecordBatchStreamWriter

    _have_pyarrow = True
except ImportError:
    _have_pyarrow = False

try:
    from snowflake.connector.arrow_context import ArrowConverterContext
    from snowflake.connector.nanoarrow_arrow_iterator import PyArrowTableIterator

    _have_nanoarrow = True
except ImportError:
    _have_nanoarrow = False

pytestmark = pytest.mark.skipif(
    not (_have_pyarrow and _have_nanoarrow),
    reason="pyarrow or nanoarrow_arrow_iterator extension not available",
)


def _ipc_bytes(arrow_type, column_meta, row_value):
    stream = BytesIO()
    field = pyarrow.field("col", arrow_type, True, column_meta)
    writer = RecordBatchStreamWriter(stream, pyarrow.schema([field]))
    writer.write_batch(
        RecordBatch.from_arrays([pyarrow.array([row_value], type=arrow_type)], ["col"])
    )
    writer.close()
    stream.seek(0)
    return stream.read()


def _run(logical_type, scale, row_value, force_microsecond_precision):
    meta = {"logicalType": logical_type, "scale": str(scale)}
    data = _ipc_bytes(pyarrow.int64(), meta, row_value)
    ctx = ArrowConverterContext()
    ctx._timezone = "UTC"
    it = PyArrowTableIterator(
        None, data, ctx, False, False, False, False, force_microsecond_precision
    )
    return next(it)


def _to_nanoseconds(dt):
    # Exact integer epoch nanoseconds for a tz-aware UTC datetime.
    secs = calendar.timegm(dt.utctimetuple())
    return secs * 1_000_000_000 + dt.microsecond * 1000


# TIMESTAMP_NTZ/LTZ at scale 7 are sent by the server as a plain int64 (units of
# 10 ** (9 - scale) nanoseconds). force_microsecond_precision must truncate them
# to microseconds so the timestamp[us] column holds microsecond values.
@pytest.mark.parametrize("logical_type", ["TIMESTAMP_NTZ", "TIMESTAMP_LTZ"])
@pytest.mark.parametrize(
    "dt",
    [
        datetime(2024, 1, 1, 12, 34, 56, 123456, tzinfo=timezone.utc),
        datetime(2020, 6, 15, 0, 0, 0, tzinfo=timezone.utc),
    ],
)
def test_force_microsecond_precision_scale7_truncates_to_micros(logical_type, dt):
    ns = _to_nanoseconds(dt)
    stored = ns // 100  # scale 7: 10 ** (9 - 7) == 100 nanoseconds per unit
    expected_us = ns // 1000

    table = _run(logical_type, 7, stored, True)
    col = table.column("col")

    # Schema must be microsecond precision.
    assert col.type.unit == "us"

    # Value must be microseconds, not the raw nanoseconds.
    assert col.cast("int64")[0].as_py() == expected_us

    # Converting back to a datetime must not raise and must match the input.
    if logical_type == "TIMESTAMP_NTZ":
        # NTZ columns are timezone-naive (UTC).
        assert col[0].as_py() == dt.replace(tzinfo=None)
    else:
        assert col[0].as_py() == dt


@pytest.mark.parametrize("logical_type", ["TIMESTAMP_NTZ", "TIMESTAMP_LTZ"])
def test_without_force_microsecond_precision_scale7_stays_nanoseconds(logical_type):
    dt = datetime(2024, 1, 1, 12, 34, 56, 123456, tzinfo=timezone.utc)
    ns = _to_nanoseconds(dt)
    stored = ns // 100  # scale 7

    table = _run(logical_type, 7, stored, False)
    col = table.column("col")

    # Without the flag the column stays nanosecond precision.
    assert col.type.unit == "ns"
    assert col.cast("int64")[0].as_py() == ns
