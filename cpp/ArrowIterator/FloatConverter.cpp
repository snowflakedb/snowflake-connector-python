/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "FloatConverter.hpp"

namespace sf
{

/** snowflake float is 64-precision, which refers to double here */
FloatConverter::FloatConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::DoubleArray>(array))
{
}

PyObject* FloatConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    return PyFloat_FromDouble(m_array->Value(rowIndex));
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
