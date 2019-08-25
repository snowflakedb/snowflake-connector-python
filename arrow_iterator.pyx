#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# distutils: language = c++

from logging import getLogger
from cpython.ref cimport PyObject

logger = getLogger(__name__)

cdef extern from "cpp/ArrowIterator/CArrowChunkIterator.hpp" namespace "sf":
    cdef cppclass CArrowChunkIterator:
        CArrowChunkIterator(PyObject* context)

        void addRecordBatch(PyObject * rb)

        PyObject *nextRow();

        void reset();


cdef class PyArrowChunkIterator:
    cdef CArrowChunkIterator* cIterator
    cdef PyObject* cret

    def __cinit__(PyArrowChunkIterator self, object arrow_stream_reader, object arrow_context):
        self.cIterator = new CArrowChunkIterator(<PyObject*>arrow_context)
        for rb in arrow_stream_reader:
            self.cIterator.addRecordBatch(<PyObject*>rb)
        self.cIterator.reset()

    def __dealloc__(PyArrowChunkIterator self):
        del self.cIterator

    def __next__(PyArrowChunkIterator self):
        cret = self.cIterator.nextRow()
        if not cret:
            logger.error("Internal error from CArrowChunkIterator\n")
            # it looks like this line can help us get into python and detect the global variable immediately
            # however, this log will not show up for unclear reason
        ret = <object>cret

        if ret is None:
            raise StopIteration
        else:
            return ret
