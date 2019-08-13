/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "DateConverter.hpp"
#include "Python/Helpers.hpp"

namespace sf
{
Logger DateConverter::logger("snowflake.connector.DateConverter");

py::UniqueRef& DateConverter::m_pyDatetimeDate()
{
  static py::UniqueRef pyDatetimeDate;
  if (pyDatetimeDate.empty())
  {
    py::PyUniqueLock lock;
    py::UniqueRef pyDatetimeModule;
    arrow::Status status = py::importPythonModule("datetime", pyDatetimeModule);
    if (!status.ok())
    {
      /** TODO : How to throw an exception will be decided later */
      logger.error("import python module 'datetime' failed");
    }
    status = py::importFromModule(pyDatetimeModule, "date", pyDatetimeDate);
    if (!status.ok())
    {
      /** TODO : How to throw an exception will be decided later */
      logger.error("import python module 'datetime.date' failed");
    }
  }
  return pyDatetimeDate;
}

DateConverter::DateConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::Date32Array>(array))
{
}

PyObject* DateConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int32_t deltaDays = m_array->Value(rowIndex);
    py::PyUniqueLock lock;
    return PyObject_CallMethod(m_pyDatetimeDate().get(), "fromordinal", "i",
                               epochDay + deltaDays);
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
