/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "Python.h"
#include <memory>
#include <arrow/api.h>
#include <arrow/python/pyarrow.h>
#include <iostream>
#include "CArrowChunkIterator.hpp"

/* --------------------------------------------------------------------- */

typedef struct {
    PyObject_HEAD
    /* Type-specific fields go here. */
    std::shared_ptr<sf::CArrowChunkIterator> m_cIterator;
} ArrowChunkIteratorObject;

static int ArrowChunkIterator_init(ArrowChunkIteratorObject * self, PyObject *args)
{
    self->m_cIterator = std::make_shared<sf::CArrowChunkIterator>();
    return 0;
};

static void
ArrowChunkIterator_dealloc(ArrowChunkIteratorObject *self)
{
    Py_TYPE(self)->tp_free((PyObject *) self);
};

static PyObject * ArrowChunkIterator__next__(PyObject *self)
{
    return ((ArrowChunkIteratorObject *)self)->m_cIterator->nextRow();
};

static PyObject * ArrowChunkIterator_add_record_batch(PyObject *self, PyObject* arg)
{
    std::shared_ptr<arrow::RecordBatch> cRecordBatch;
    arrow::Status status = arrow::py::unwrap_record_batch(arg, &cRecordBatch);

    ((ArrowChunkIteratorObject *)self)->m_cIterator->addRecordBatch(cRecordBatch);

    return Py_BuildValue("");
}

static PyMethodDef ArrowChunkIterator_methods[] = {
    {"add_record_batch", (PyCFunction)ArrowChunkIterator_add_record_batch, METH_O,
     "Return the name, combining the first and last name"
    },
    {"__next__", (PyCFunction)ArrowChunkIterator__next__, METH_NOARGS, 0},
    {NULL}  /* Sentinel */
};

static PyTypeObject ArrowChunkIteratorType = {
  PyVarObject_HEAD_INIT(0, 0)
  "snowflake.connector.libarrow_iterator.ArrowChunkIterator", /*tp_name*/
  sizeof(ArrowChunkIteratorObject), /*tp_basicsize*/
  0, /*tp_itemsize*/
  (destructor)ArrowChunkIterator_dealloc, //__pyx_tp_dealloc_9snowflake_9connector_12arrow_result_ArrowResult, /*tp_dealloc*/
  0, /*tp_print*/
  0, /*tp_getattr*/
  0, /*tp_setattr*/
  #if PY_MAJOR_VERSION < 3
  0, /*tp_compare*/
  #endif
  #if PY_MAJOR_VERSION >= 3
  0, /*tp_as_async*/
  #endif
  0, /*tp_repr*/
  0, /*tp_as_number*/
  0, /*tp_as_sequence*/
  0, /*tp_as_mapping*/
  0, /*tp_hash*/
  0, /*tp_call*/
  0, /*tp_str*/
  0, /*tp_getattro*/
  0, /*tp_setattro*/
  0, /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT, /*tp_flags*/
  0, /*tp_doc*/
  0, //__pyx_tp_traverse_9snowflake_9connector_12arrow_result_ArrowResult, /*tp_traverse*/
  0, //__pyx_tp_clear_9snowflake_9connector_12arrow_result_ArrowResult, /*tp_clear*/
  0, /*tp_richcompare*/
  0, /*tp_weaklistoffset*/
  0, //__pyx_pw_9snowflake_9connector_12arrow_result_11ArrowResult_5__iter__, /*tp_iter*/
  ArrowChunkIterator__next__, /*tp_iternext*/
  ArrowChunkIterator_methods, /*tp_methods*/
  0, /*tp_members*/
  0, /*tp_getset*/
  0, /*tp_base*/
  0, /*tp_dict*/
  0, /*tp_descr_get*/
  0, /*tp_descr_set*/
  0, /*tp_dictoffset*/
  (initproc)ArrowChunkIterator_init, /*tp_init*/
  0, /*tp_alloc*/
  PyType_GenericNew,   //__pyx_tp_new_9snowflake_9connector_12arrow_result_ArrowResult, /*tp_new*/
  0, /*tp_free*/
  0, /*tp_is_gc*/
  0, /*tp_bases*/
  0, /*tp_mro*/
  0, /*tp_cache*/
  0, /*tp_subclasses*/
  0, /*tp_weaklist*/
  0, /*tp_del*/
  0, /*tp_version_tag*/
  #if PY_VERSION_HEX >= 0x030400a1
  0, /*tp_finalize*/
  #endif
  #if PY_VERSION_HEX >= 0x030800b1
  0, /*tp_vectorcall*/
  #endif
};

static PyModuleDef arrowIteratorModule = {
    PyModuleDef_HEAD_INIT,
    m_name: "libarrow_iterator",
    m_doc: "Example module that creates an extension type.",
    m_size: -1,
};

PyMODINIT_FUNC
PyInit_libarrow_iterator(void)
{
    PyObject *m;
    if (PyType_Ready(&ArrowChunkIteratorType) < 0)
        return NULL;

    m = PyModule_Create(&arrowIteratorModule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&ArrowChunkIteratorType);
    PyModule_AddObject(m, "ArrowChunkIterator", (PyObject *) &ArrowChunkIteratorType);

    arrow::py::import_pyarrow();
    return m;
}