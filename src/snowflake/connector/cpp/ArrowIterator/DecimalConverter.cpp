//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
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
    std::shared_ptr<ArrowArrayView> array, int scale)
: m_nanoarrowArrayView(array),
  m_scale(scale)
{
}

PyObject* DecimalFromDecimalConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  // TODO: FormatValue equivalent in nanoarrow?
  //std::string formatDecimalString = m_array->FormatValue(rowIndex);
  std::string formatDecimalString = "";
  if (m_scale == 0)
  {
    return PyLong_FromString(formatDecimalString.c_str(), nullptr, 0);
  }

  /** the reason we use c_str() instead of std::string here is that we may
   * meet some encoding problem with std::string */
  return PyObject_CallFunction(m_pyDecimalConstructor.get(), "s#",
                               formatDecimalString.c_str(),
                               static_cast<Py_ssize_t>(formatDecimalString.size()));
}

}  // namespace sf
