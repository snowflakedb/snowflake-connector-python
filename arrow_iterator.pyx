#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# distutils: language = c++
# cython: language_level=3

from logging import getLogger
from cpython.ref cimport PyObject
from libc.stdint cimport *
from libcpp cimport bool as c_bool
from libcpp.memory cimport shared_ptr
from libcpp.string cimport string as c_string
from libcpp.vector cimport vector
from .errors import (Error, OperationalError)
from .errorcode import ER_FAILED_TO_READ_ARROW_STREAM

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
        CArrowChunkIterator(PyObject* context, vector[shared_ptr[CRecordBatch]]* batches) except +

    cdef cppclass DictCArrowChunkIterator(CArrowChunkIterator):
        DictCArrowChunkIterator(PyObject* context, vector[shared_ptr[CRecordBatch]]* batches) except +


cdef extern from "cpp/ArrowIterator/CArrowTableIterator.hpp" namespace "sf":
    cdef cppclass CArrowTableIterator(CArrowIterator):
        CArrowTableIterator(PyObject* context, vector[shared_ptr[CRecordBatch]]* batches) except +


cdef extern from "arrow/api.h" namespace "arrow" nogil:
    cdef cppclass CStatus "arrow::Status":
        CStatus()

        c_string ToString()
        c_string message()

        c_bool ok()
        c_bool IsIOError()
        c_bool IsOutOfMemory()
        c_bool IsInvalid()
        c_bool IsKeyError()
        c_bool IsNotImplemented()
        c_bool IsTypeError()
        c_bool IsCapacityError()
        c_bool IsIndexError()
        c_bool IsSerializationError()


    cdef cppclass CBuffer" arrow::Buffer":
        CBuffer(const uint8_t* data, int64_t size)

    cdef cppclass CRecordBatch" arrow::RecordBatch"

    cdef cppclass CRecordBatchReader" arrow::RecordBatchReader":
        CStatus ReadNext(shared_ptr[CRecordBatch]* batch)


cdef extern from "arrow/ipc/api.h" namespace "arrow::ipc" nogil:
    cdef cppclass CRecordBatchStreamReader \
            " arrow::ipc::RecordBatchStreamReader"(CRecordBatchReader):
        @staticmethod
        CStatus Open(const InputStream* stream,
                     shared_ptr[CRecordBatchReader]* out)


cdef extern from "arrow/io/api.h" namespace "arrow::io" nogil:
    enum FileMode" arrow::io::FileMode::type":
        FileMode_READ" arrow::io::FileMode::READ"
        FileMode_WRITE" arrow::io::FileMode::WRITE"
        FileMode_READWRITE" arrow::io::FileMode::READWRITE"

    cdef cppclass FileInterface:
        CStatus Close()
        CStatus Tell(int64_t* position)
        FileMode mode()
        c_bool closed()

    cdef cppclass Readable:
        # put overload under a different name to avoid cython bug with multiple
        # layers of inheritance
        CStatus ReadBuffer" Read"(int64_t nbytes, shared_ptr[CBuffer]* out)
        CStatus Read(int64_t nbytes, int64_t* bytes_read, uint8_t* out)

    cdef cppclass InputStream(FileInterface, Readable):
        pass

    cdef cppclass Seekable:
        CStatus Seek(int64_t position)

    cdef cppclass RandomAccessFile(InputStream, Seekable):
        CStatus GetSize(int64_t* size)

        CStatus ReadAt(int64_t position, int64_t nbytes,
                       int64_t* bytes_read, uint8_t* buffer)
        CStatus ReadAt(int64_t position, int64_t nbytes,
                       shared_ptr[CBuffer]* out)
        c_bool supports_zero_copy()


cdef extern from "arrow/python/api.h" namespace "arrow::py" nogil:
    cdef cppclass PyReadableFile(RandomAccessFile):
        PyReadableFile(object fo)


cdef class EmptyPyArrowIterator:

    def __next__(self):
       raise StopIteration

    def init(self, str iter_unit):
        pass


cdef class PyArrowIterator(EmptyPyArrowIterator):
    cdef object context
    cdef CArrowIterator* cIterator
    cdef str unit
    cdef PyObject* cret
    cdef vector[shared_ptr[CRecordBatch]] batches
    cdef object use_dict_result

    def __cinit__(self, object py_inputstream, object arrow_context, object use_dict_result):
        cdef shared_ptr[InputStream] input_stream
        cdef shared_ptr[CRecordBatchReader] reader
        cdef shared_ptr[CRecordBatch] record_batch
        input_stream.reset(new PyReadableFile(py_inputstream))
        cdef CStatus ret = CRecordBatchStreamReader.Open(input_stream.get(), &reader)
        if not ret.ok():
            Error.errorhandler_wrapper(
                None,
                None,
                OperationalError,
                {
                    u'msg': u'Failed to open arrow stream: ' + ret.message(),
                    u'errno': ER_FAILED_TO_READ_ARROW_STREAM
                })

        while True:
            ret = reader.get().ReadNext(&record_batch)
            if not ret.ok():
                Error.errorhandler_wrapper(
                    None,
                    None,
                    OperationalError,
                    {
                        u'msg': u'Failed to read next arrow batch: ' + ret.message(),
                        u'errno': ER_FAILED_TO_READ_ARROW_STREAM
                    })

            if record_batch.get() is NULL:
                break

            self.batches.push_back(record_batch)

        logger.debug("Batches read: %d", self.batches.size())

        self.context = arrow_context
        self.cIterator = NULL
        self.unit = ''
        self.use_dict_result = use_dict_result

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
            self.cIterator = new CArrowChunkIterator(<PyObject*>self.context, &self.batches) if not self.use_dict_result \
                else new DictCArrowChunkIterator(<PyObject*>self.context, &self.batches)

        elif iter_unit == TABLE_UNIT:
            self.cIterator = new CArrowTableIterator(<PyObject*>self.context, &self.batches)
        self.unit = iter_unit

