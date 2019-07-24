#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# distutils: language = c++

from cpython.ref cimport PyObject

cdef extern from "cpp/ArrowIterator/CArrowChunkIterator.hpp" namespace "sf":
    cdef cppclass CArrowChunkIterator:
        CArrowChunkIterator()

        void addRecordBatch(PyObject * rb)

        PyObject *nextRow();


cdef class PyArrowChunkIterator:
    cdef CArrowChunkIterator thisptr

    def __cinit__(self):
        self.thisptr = CArrowChunkIterator()

    def add_record_batch(self, rb):
        self.thisptr.addRecordBatch(<PyObject *>rb)

    def __next__(self):
        ret = <object>self.thisptr.nextRow()
        if ret is None:
            raise StopIteration
        else:
            return ret
