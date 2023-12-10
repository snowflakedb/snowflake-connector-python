#define Py_LIMITED_API 0x03080000

#include "Python/Common.hpp"

#include <memory>
#include <vector>

#include "CArrowIterator.hpp"

#ifndef Py_PYTHON_H
    #error Python headers needed to compile C extensions, please install development version of Python.
#elif PY_VERSION_HEX < 0x03080000
    #error This requires Python 3.8+.
#endif

// Helper functions.

namespace sf {

static bool isPyarrowInstalled() {
  PyObject *pyarrowModule = PyImport_ImportModule("pyarrow");
  if (pyarrowModule) {
    // We have pyarrow.
    Py_XDECREF(pyarrowModule);
    return true;
  } else {
    // No pyarrow. Clear the exception.
    PyErr_Clear();
    return false;
  }
}

// Python class structures.

struct EmptyPyArrowIteratorObject {
    PyObject_HEAD
};

struct PyArrowIteratorObject {
    EmptyPyArrowIteratorObject base;
    // TODO: Fields.

    PyObject *context;
    CArrowIterator* cIterator;
    PyObject *unit;
    std::shared_ptr<ReturnVal> cret;
    PyObject *use_dict_result;
    PyObject *cursor;
    std::vector<uintptr_t> nanoarrow_Table;
    std::vector<uintptr_t> nanoarrow_Schema;
    PyObject *table_returned;
    char* arrow_bytes;
    int64_t arrow_bytes_size;

    // This is the flag indicating whether fetch data as numpy datatypes or not. The flag
    // is passed from the constructor of SnowflakeConnection class. Note, only FIXED, REAL
    // and TIMESTAMP_NTZ will be converted into numpy data types, all other sql types will
    // still be converted into native python types.
    // https://docs.snowflake.com/en/user-guide/sqlalchemy.html#numpy-data-type-support
    PyObject *use_numpy;
    PyObject *number_to_decimal;
    PyObject *pyarrow_table;
};

struct PyArrowRowIteratorObject {
    PyArrowIteratorObject base;
};

struct PyArrowTableIteratorObject {
    PyArrowIteratorObject base;
};

struct ArrowIteratorModuleState {
    // Types.
    PyTypeObject* typeEmptyPyArrowIterator;
    PyTypeObject* typePyArrowIterator;
    PyTypeObject* typePyArrowRowIterator;
    PyTypeObject* typePyArrowTableIterator;

    // Module-level variables.
    bool isPyarrowInstalled;
};

// Member functions of classes.

//static PyObject *EmptyPyArrowIterator_init(PyObject *self) {
//  // TODO
//  return nullptr;
//}

static PyObject *EmptyPyArrowIterator_iter(PyObject *self) {
    Py_INCREF(self);
    return self;
}

static PyObject *EmptyPyArrowIterator_next(PyObject *self) {
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
}

static PyType_Slot EmptyPyArrowIterator_slots[] = {
    // TODO: {Py_tp_init, (void *)EmptyPyArrowIterator_init},
    {Py_tp_iter, (void *)EmptyPyArrowIterator_iter},
    {Py_tp_iternext, (void *)EmptyPyArrowIterator_next},
    {0, nullptr},
};

// TODO: PyArrowIterator::init
// TODO: PyArrowIterator::__dealloc__

// TODO: Can't we inherit our parent's?
static PyObject *PyArrowIterator_iter(PyObject *self) {
    Py_INCREF(self);
    return self;
}

static PyType_Slot PyArrowIterator_slots[] = {
    // TODO: {Py_tp_init, (void *)PyArrowIterator_init},
    // TODO: dealloc {Py_tp_init, (void *)PyArrowIterator_dealloc},
    {Py_tp_iter, (void *)PyArrowIterator_iter},
    {0, nullptr},
};

// TODO: PyArrowRowIterator::init

static PyObject *PyArrowRowIterator_next(PyObject *self) {
    // TODO
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
}

static PyType_Slot PyArrowRowIterator_slots[] = {
    // TODO: {Py_tp_init, (void *)PyArrowRowIterator_init},
    {Py_tp_iternext, (void *)PyArrowRowIterator_next},
    {0, nullptr},
};

// TODO: PyArrowTableIterator::init

static PyObject *PyArrowTableIterator_next(PyObject *self) {
    // TODO
    PyErr_SetNone(PyExc_StopIteration);
    return nullptr;
}

static PyType_Slot PyArrowTableIterator_slots[] = {
    // TODO: {Py_tp_init, (void *)PyArrowTableIterator_init},
    {Py_tp_iternext, (void *)PyArrowTableIterator_next},
    {0, nullptr},
};


// Class specs.

static PyType_Spec EmptyPyArrowIterator_spec {
    /*name=*/"snowflake.connector.nanoarrow_arrow_iterator.EmptyPyArrowIterator",
    /*basicsize=*/sizeof(EmptyPyArrowIteratorObject),
    /*itemsize=*/0,
    /*flags=*/Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    /*slots=*/EmptyPyArrowIterator_slots,
};

static PyType_Spec PyArrowIterator_spec {
    /*name=*/"snowflake.connector.nanoarrow_arrow_iterator.PyArrowIterator",
    /*basicsize=*/sizeof(PyArrowIteratorObject),
    /*itemsize=*/0,
    /*flags=*/Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    /*slots=*/PyArrowIterator_slots,
};

static PyType_Spec PyArrowRowIterator_spec {
    /*name=*/"snowflake.connector.nanoarrow_arrow_iterator.PyArrowRowIterator",
    /*basicsize=*/sizeof(PyArrowRowIteratorObject),
    /*itemsize=*/0,
    /*flags=*/Py_TPFLAGS_DEFAULT,
    /*slots=*/PyArrowRowIterator_slots,
};


static PyType_Spec PyArrowTableIterator_spec {
    /*name=*/"snowflake.connector.nanoarrow_arrow_iterator.PyArrowTableIterator",
    /*basicsize=*/sizeof(PyArrowTableIteratorObject),
    /*itemsize=*/0,
    /*flags=*/Py_TPFLAGS_DEFAULT,
    /*slots=*/PyArrowTableIterator_slots,
};

// TODO

static ArrowIteratorModuleState *getArrowIteratorModuleState(PyObject *module) {
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (ArrowIteratorModuleState *)(state);
}

static PyMethodDef arrowIteratorModuleMethods[] = {
    // TODO: Do we need this?
    //{"isPyarrowInstalled", isPyarrowInstalled, METH_VARARGS,
    // "Check if pyarrow is installed."},
    {nullptr, nullptr, 0, nullptr},
};

static int arrow_iterator_module_exec(PyObject *m) {
    const auto createType = [m](const char *name, PyType_Spec &spec, PyObject *base) -> py::UniqueRef {
        // After removing support for Python 3.9, we should be
        // able to pass `&base` directly. Until then, we need
        // to create a 1-item tuple.
        py::UniqueRef basesTuple;
        if (base != nullptr) {
            basesTuple.reset(PyTuple_New(/*len=*/1));
            if (basesTuple.get() == nullptr) {
                return py::UniqueRef();
            }
            // Note that `PyTuple_SetItem` steals a reference to `base`.
            Py_INCREF(base);
            const int ret = PyTuple_SetItem(basesTuple.get(), 0, base);
            assert(ret == 0);
        }

        // After removing support for Python 3.9, we should use
        // `PyType_FromModuleAndSpec` here.
        py::UniqueRef newType(PyType_FromSpecWithBases(&spec, basesTuple.get()));
        if (newType.get() == nullptr) {
            return py::UniqueRef();
        }

        // Register the type with the module. Note that `PyModule_AddObject`
        // steals ownership on success, so we increment the refcount. After
        // removing support for Python 3.9, we can use `PyModule_AddObjectRef`
        // in the limited API, which lets us skip some of this refcount
        // handling.
        Py_INCREF(newType.get());
        if (PyModule_AddObject(m, name, newType.get()) < 0) {
            Py_DECREF(newType.get());
            return py::UniqueRef();
        }
        return py::UniqueRef(newType.release());
    };

    py::UniqueRef typeEmptyPyArrowIterator = createType("EmptyPyArrowIterator", EmptyPyArrowIterator_spec, nullptr);
    if (typeEmptyPyArrowIterator.get() == nullptr) {
      return -1;
    }
    py::UniqueRef typePyArrowIterator = createType("PyArrowIterator", PyArrowIterator_spec, typeEmptyPyArrowIterator.get());
    if (typePyArrowIterator.get() == nullptr) {
      return -1;
    }
    py::UniqueRef typePyArrowRowIterator = createType("PyArrowRowIterator", PyArrowRowIterator_spec, typePyArrowIterator.get());
    if (typePyArrowRowIterator.get() == nullptr) {
      return -1;
    }
    py::UniqueRef typePyArrowTableIterator = createType("PyArrowTableIterator", PyArrowTableIterator_spec, typePyArrowIterator.get());
    if (typePyArrowTableIterator.get() == nullptr) {
      return -1;
    }

    // NOTE: After this point, we can no longer return an error,
    // since things might not be cleaned up.

    ArrowIteratorModuleState *state = getArrowIteratorModuleState(m);

    // Initialize types.
    state->typeEmptyPyArrowIterator = (PyTypeObject *)typeEmptyPyArrowIterator.release();
    state->typePyArrowIterator = (PyTypeObject *)typePyArrowIterator.release();
    state->typePyArrowRowIterator = (PyTypeObject *)typePyArrowRowIterator.release();
    state->typePyArrowTableIterator = (PyTypeObject *)typePyArrowTableIterator.release();

    // Initialize module-level variables.
    state->isPyarrowInstalled = isPyarrowInstalled();

    return 0;
}

static PyModuleDef_Slot arrowIteratorModule_slots[] = {
    {Py_mod_exec, (void *)arrow_iterator_module_exec},
    {0, nullptr},
};

static PyModuleDef arrowIteratorModule_def = {
    /*m_base=*/PyModuleDef_HEAD_INIT,
    /*m_name=*/"nanoarrow_arrow_iterator",
    /*m_doc=*/nullptr,
    /*m_size=*/sizeof(ArrowIteratorModuleState),
    /*m_methods=*/arrowIteratorModuleMethods,
    /*m_slots=*/arrowIteratorModule_slots,
};

}

PyMODINIT_FUNC
PyInit_nanoarrow_arrow_iterator(void)
{
    return PyModuleDef_Init(&sf::arrowIteratorModule_def);
}
