#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# distutils: language = c++
# cython: language_level=3

from logging import getLogger
from cpython.ref cimport PyObject

logger = getLogger(__name__)

'''
the unit in this iterator
EMPTY_UNIT: default
ROW_UNIT: fetch row by row if the user call `fetchone()`
TABLE_UNIT: fetch one arrow table if the user call `fetch_pandas()`
'''
ROW_UNIT, TABLE_UNIT, EMPTY_UNIT = 'row', 'table', ''


cdef extern from "cpp/ArrowIterator/CArrowIterator.hpp" namespace "sf":
    cdef cppclass CArrowIterator:
        PyObject* next();


cdef extern from "cpp/ArrowIterator/CArrowChunkIterator.hpp" namespace "sf":
    cdef cppclass CArrowChunkIterator(CArrowIterator):
        CArrowChunkIterator(PyObject* context, PyObject* batches) except +


cdef extern from "cpp/ArrowIterator/CArrowTableIterator.hpp" namespace "sf":
    cdef cppclass CArrowTableIterator(CArrowIterator):
        CArrowTableIterator(PyObject* context, PyObject* batches) except +


cdef class EmptyPyArrowIterator:
    def __cinit__(self, object arrow_stream_reader, object arrow_context):
        pass

    def __dealloc__(self):
        pass

    def __next__(self):
       raise StopIteration

    def init(self, str iter_unit):
        pass


cdef class PyArrowIterator(EmptyPyArrowIterator):
    cdef object context
    cdef CArrowIterator* cIterator
    cdef str unit
    cdef PyObject* cret
    cdef list batches

    def __cinit__(self, object arrow_stream_reader, object arrow_context):
        self.batches = []
        for rb in arrow_stream_reader:
            self.batches.append(rb)
        self.context = arrow_context
        self.cIterator = NULL
        self.unit = ''

    def __dealloc__(self):
        del self.cIterator

    def __next__(self):
        self.cret = self.cIterator.next()

        if not self.cret:
            logger.error("Internal error from CArrowIterator\n")
            # it looks like this line can help us get into python and detect the global variable immediately
            # however, this log will not show up for unclear reason
        ret = <object>self.cret

        if ret is None:
            raise StopIteration
        else:
            return ret

    def init(self, str iter_unit):
        # init chunk (row) iterator or table iterator
        if iter_unit != ROW_UNIT and iter_unit != TABLE_UNIT:
            raise NotImplementedError
        elif iter_unit == ROW_UNIT:
            self.cIterator = new CArrowChunkIterator(<PyObject*>self.context, <PyObject*>self.batches)
        elif iter_unit == TABLE_UNIT:
            self.cIterator = new CArrowTableIterator(<PyObject*>self.context, <PyObject*>self.batches)
        self.unit = iter_unit

