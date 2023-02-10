# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# cython: language_level = 3

from libc.stdint cimport int64_t, int8_t, uint8_t


cdef extern from "nanoarrow.h":
    struct ArrowSchema:
        const char* format
        int64_t n_children
        void (*release)(ArrowSchema*)

    struct ArrowArray:
        int64_t length
        int64_t null_count
        int64_t offset
        const void** buffers
        void (*release)(ArrowArray*)

    struct ArrowArrayStream:
        int (*get_schema)(ArrowArrayStream* stream, ArrowSchema* out)

    ctypedef int ArrowErrorCode

    enum ArrowType:
        NANOARROW_TYPE_UNINITIALIZED = 0
        NANOARROW_TYPE_NA = 1
        NANOARROW_TYPE_BOOL
        NANOARROW_TYPE_UINT8
        NANOARROW_TYPE_INT8
        NANOARROW_TYPE_UINT16
        NANOARROW_TYPE_INT16
        NANOARROW_TYPE_UINT32
        NANOARROW_TYPE_INT32
        NANOARROW_TYPE_UINT64
        NANOARROW_TYPE_INT64
        NANOARROW_TYPE_HALF_FLOAT
        NANOARROW_TYPE_FLOAT
        NANOARROW_TYPE_DOUBLE
        NANOARROW_TYPE_STRING
        NANOARROW_TYPE_BINARY
        NANOARROW_TYPE_FIXED_SIZE_BINARY
        NANOARROW_TYPE_DATE32
        NANOARROW_TYPE_DATE64
        NANOARROW_TYPE_TIMESTAMP
        NANOARROW_TYPE_TIME32
        NANOARROW_TYPE_TIME64
        NANOARROW_TYPE_INTERVAL_MONTHS
        NANOARROW_TYPE_INTERVAL_DAY_TIME
        NANOARROW_TYPE_DECIMAL128
        NANOARROW_TYPE_DECIMAL256
        NANOARROW_TYPE_LIST
        NANOARROW_TYPE_STRUCT
        NANOARROW_TYPE_SPARSE_UNION
        NANOARROW_TYPE_DENSE_UNION
        NANOARROW_TYPE_DICTIONARY
        NANOARROW_TYPE_MAP
        NANOARROW_TYPE_EXTENSION
        NANOARROW_TYPE_FIXED_SIZE_LIST
        NANOARROW_TYPE_DURATION
        NANOARROW_TYPE_LARGE_STRING
        NANOARROW_TYPE_LARGE_BINARY
        NANOARROW_TYPE_LARGE_LIST
        NANOARROW_TYPE_INTERVAL_MONTH_DAY_NANO

    enum ArrowBufferType:
        NANOARROW_BUFFER_TYPE_NONE
        NANOARROW_BUFFER_TYPE_VALIDITY
        NANOARROW_BUFFER_TYPE_TYPE_ID
        NANOARROW_BUFFER_TYPE_UNION_OFFSET
        NANOARROW_BUFFER_TYPE_DATA_OFFSET
        NANOARROW_BUFFER_TYPE_DATA

    struct ArrowError:
        pass

    const char* ArrowErrorMessage(ArrowError* error)

    struct ArrowLayout:
        ArrowBufferType buffer_type[3]
        int64_t element_size_bits[3]
        int64_t child_size_elements

    cdef union buffer_data:
        const void* data
        const int8_t* as_int8
        const uint8_t* as_uint8

    struct ArrowBufferView:
        buffer_data data
        int64_t size_bytes

    struct ArrowBuffer:
        uint8_t* data
        int64_t size_bytes

    struct ArrowBitmap:
        ArrowBuffer buffer
        int64_t size_bits

    struct ArrowArrayView:
        ArrowArray* array
        ArrowType storage_type
        ArrowLayout layout
        ArrowBufferView buffer_views[3]
        int64_t n_children
        ArrowArrayView** children

    ArrowErrorCode ArrowArrayViewInitFromSchema(ArrowArrayView* array_view, ArrowSchema* schema, ArrowError* error)
    ArrowErrorCode ArrowArrayViewSetArray(ArrowArrayView* array_view, ArrowArray* array, ArrowError* error)
    int64_t ArrowBitCountSet(const uint8_t* bits, int64_t i_from, int64_t i_to)
