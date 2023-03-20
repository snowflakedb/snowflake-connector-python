//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#include "Python/Common.hpp"
#include "DecimalConverter.hpp"
#include "Python/Helpers.hpp"
#include <memory>
#include <string>

namespace sf
{

DecimalBaseConverter::DecimalBaseConverter()
: m_pyDecimalConstructor(initPyDecimalConstructor())
{
}

py::UniqueRef& DecimalBaseConverter::initPyDecimalConstructor()
{
  static py::UniqueRef pyDecimalConstructor;
  if (pyDecimalConstructor.empty())
  {
    py::UniqueRef decimalModule;
    py::importPythonModule("decimal", decimalModule);
    py::importFromModule(decimalModule, "Decimal", pyDecimalConstructor);
    Py_XINCREF(pyDecimalConstructor.get());
  }

  return pyDecimalConstructor;
}

DecimalFromDecimalConverter::DecimalFromDecimalConverter(
    PyObject* context,
    ArrowArrayView* array, int scale)
: m_array(array),
  m_context(context),
  m_scale(scale)
{
}

PyObject* DecimalFromDecimalConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t bytes_start = 16 * (m_array->array->offset + rowIndex);
  const char* ptr_start = m_array->buffer_views[1].data.as_char;
  PyObject* int128_bytes = PyBytes_FromStringAndSize(&(ptr_start[bytes_start]), 16);
  return PyObject_CallMethod(m_context, "DECIMAL128_to_decimal", "Si", int128_bytes, m_scale);
}

}  // namespace sf
