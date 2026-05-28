from __future__ import annotations

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
    from snowflake.connector.nanoarrow_arrow_iterator import (
        PyArrowRowIterator as NanoarrowPyArrowRowIterator,
    )

    _have_nanoarrow = True
except ImportError:
    _have_nanoarrow = False

pytestmark = pytest.mark.skipif(
    not (_have_pyarrow and _have_nanoarrow),
    reason="pyarrow or nanoarrow_arrow_iterator extension not available",
)

_INVALID_SCALES = [-1, 10, 100, -100]
_VALID_SCALES = list(range(10))


def _ipc_bytes(arrow_type, column_meta, row_value):
    stream = BytesIO()
    field = pyarrow.field("col", arrow_type, True, column_meta)
    writer = RecordBatchStreamWriter(stream, pyarrow.schema([field]))
    writer.write_batch(
        RecordBatch.from_arrays(
            [pyarrow.array([row_value], type=arrow_type)], ["col"]
        )
    )
    writer.close()
    stream.seek(0)
    return stream.read()


def _iterate(data):
    ctx = ArrowConverterContext()
    it = NanoarrowPyArrowRowIterator(None, data, ctx, False, False, False, True)
    return list(it)


# --- Invalid scale: must raise ---


@pytest.mark.parametrize("scale", _INVALID_SCALES)
def test_time_invalid_scale_raises(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIME", "scale": str(scale)}, 0
    )
    with pytest.raises(Exception):
        _iterate(data)


@pytest.mark.parametrize("scale", _INVALID_SCALES)
def test_timestamp_ntz_invalid_scale_raises(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIMESTAMP_NTZ", "scale": str(scale)}, 0
    )
    with pytest.raises(Exception):
        _iterate(data)


@pytest.mark.parametrize("scale", _INVALID_SCALES)
def test_timestamp_ltz_invalid_scale_raises(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIMESTAMP_LTZ", "scale": str(scale)}, 0
    )
    with pytest.raises(Exception):
        _iterate(data)


@pytest.mark.parametrize("scale", _INVALID_SCALES)
def test_timestamp_tz_invalid_scale_raises(scale):
    # TIMESTAMP_TZ with byteLength=8 uses a two-field struct (epoch + timezone)
    arrow_type = pyarrow.struct(
        [
            pyarrow.field("epoch", pyarrow.int64()),
            pyarrow.field("timezone", pyarrow.int32()),
        ]
    )
    data = _ipc_bytes(
        arrow_type,
        {"logicalType": "TIMESTAMP_TZ", "scale": str(scale), "byteLength": "8"},
        {"epoch": 0, "timezone": 1440},
    )
    with pytest.raises(Exception):
        _iterate(data)


# --- Valid scale (0-9): must NOT raise ---


@pytest.mark.parametrize("scale", _VALID_SCALES)
def test_time_valid_scale_accepted(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIME", "scale": str(scale)}, 0
    )
    _iterate(data)


@pytest.mark.parametrize("scale", _VALID_SCALES)
def test_timestamp_ntz_valid_scale_accepted(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIMESTAMP_NTZ", "scale": str(scale)}, 0
    )
    _iterate(data)


@pytest.mark.parametrize("scale", _VALID_SCALES)
def test_timestamp_ltz_valid_scale_accepted(scale):
    data = _ipc_bytes(
        pyarrow.int64(), {"logicalType": "TIMESTAMP_LTZ", "scale": str(scale)}, 0
    )
    _iterate(data)


@pytest.mark.parametrize("scale", _VALID_SCALES)
def test_timestamp_tz_valid_scale_accepted(scale):
    arrow_type = pyarrow.struct(
        [
            pyarrow.field("epoch", pyarrow.int64()),
            pyarrow.field("timezone", pyarrow.int32()),
        ]
    )
    data = _ipc_bytes(
        arrow_type,
        {"logicalType": "TIMESTAMP_TZ", "scale": str(scale), "byteLength": "8"},
        {"epoch": 0, "timezone": 1440},
    )
    _iterate(data)
