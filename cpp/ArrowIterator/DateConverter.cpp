/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "DateConverter.hpp"
#include "Python/Helpers.hpp"

namespace sf
{
Logger DateConverter::logger("snowflake.connector.DateConverter");

py::UniqueRef& DateConverter::initPyDatetimeDate()
{
  static py::UniqueRef pyDatetimeDate;
  if (pyDatetimeDate.empty())
  {
    py::UniqueRef pyDatetimeModule;
    py::importPythonModule("datetime", pyDatetimeModule);
    py::importFromModule(pyDatetimeModule, "date", pyDatetimeDate);
    Py_XINCREF(pyDatetimeDate.get());
  }
  return pyDatetimeDate;
}

DateConverter::DateConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::Date32Array>(array)),
  m_pyDatetimeDate(initPyDatetimeDate())
{
}

PyObject* DateConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int32_t deltaDays = m_array->Value(rowIndex);
    return PyObject_CallMethod(m_pyDatetimeDate.get(), "fromordinal", "i",
                               epochDay + deltaDays);
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
