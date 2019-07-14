#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from decimal import Context
from logging import getLogger
from datetime import datetime, timedelta, date

logger = getLogger(__name__)

ZERO_EPOCH = datetime.utcfromtimestamp(0)

cdef class ArrowChunkIterator:

    cdef:
        list _batches
        int _column_count
        int _batch_count
        int _batch_index
        int _index_in_batch
        int _row_count_in_batch
        list _current_batch

    def __init__(self, arrow_stream_reader, meta):
        self._batches = []
        for record_batch in arrow_stream_reader:
            converters = []
            for index, column in enumerate(record_batch.columns):
                converters.append(ColumnConverter.init_converter(column, meta[index]))
            self._batches.append(converters)

        self._column_count = len(self._batches[0])
        self._batch_count = len(self._batches)
        self._batch_index = -1
        self._index_in_batch = -1
        self._row_count_in_batch = 0
        self._current_batch = None

    def next(self):
        return self.__next__()

    def __next__(self):
        self._index_in_batch += 1
        if self._index_in_batch < self._row_count_in_batch:
            return self._return_row()
        else:
            self._batch_index += 1
            if self._batch_index < self._batch_count:
                self._current_batch = self._batches[self._batch_index]
                self._index_in_batch = 0
                self._row_count_in_batch = self._current_batch[0].row_count()
                return self._return_row()

        raise StopIteration

    cdef _return_row(self):
        row = []
        for col in self._current_batch:
            row.append(col.to_python_native(self._index_in_batch))

        return row


cdef class ColumnConverter:
    #Convert from arrow data into python native data types

    cdef object _arrow_column_array
    cdef object _meta

    def __init__(self, arrow_column_array, meta):
        """
        Base Column Converter constructor
        :param arrow_column_array: arrow array
        :param meta: column metadata, which is a tuple with same form as cursor.description
        """
        self._arrow_column_array = arrow_column_array
        self._meta = meta

    def to_python_native(self, index):
        return self._arrow_column_array[index].as_py()

    def row_count(self):
        return len(self._arrow_column_array)

    @staticmethod
    def init_converter(column_array, meta):
        # index 1 is type code
        if meta[1] == 'FIXED':
            return FixedColumnConverter(column_array, meta)
        else:
            return ColumnConverter(column_array, meta)

cdef class FixedColumnConverter(ColumnConverter):
    cdef int _scale
    cdef object _convert_method

    def __init__(self, arrow_column_array, meta):
        super().__init__(arrow_column_array, meta)
        self._scale = meta[5]
        if self._scale == 0:
            self._convert_method = self._to_int
        else:
            self._decimal_ctx = Context(prec=meta['precision'])
            self._convert_method = self._to_decimal

    def to_python_native(self, index):
        val = self._arrow_column_array[index]
        return self._convert_method(val)

    def _to_int(self, val):
        return val.as_py()

    def _to_decimal(self, val):
        return 0

cdef class DateColumnConverter(ColumnConverter):

    def __init__(self, arrow_column_array, meta):
        super().__init__(arrow_column_array, meta)

    def to_python_native(self, index):
        value = self._arrow_column_array[index]
        try:
            return datetime.utcfromtimestamp(value.as_py() * 86400).date()
        except OSError as e:
            logger.debug("Failed to convert: %s", e)
            ts = ZERO_EPOCH + timedelta(
                seconds=value * (24 * 60 * 60))
            return date(ts.year, ts.month, ts.day)
