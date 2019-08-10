/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "BinaryConverter.hpp"

namespace sf
{
BinaryConverter::BinaryConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::BinaryArray>(array))
{
}

PyObject* BinaryConverter::toPyObject(int64_t rowIndex)
{
  if (m_array->IsValid(rowIndex))
  {
    arrow::util::string_view sv = m_array->GetView(rowIndex);
    return PyByteArray_FromStringAndSize(sv.data(), sv.size());
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
