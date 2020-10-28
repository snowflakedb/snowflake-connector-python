//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#include "BinaryConverter.hpp"

namespace sf
{
Logger* BinaryConverter::logger = new Logger("snowflake.connector.BinaryConverter");

BinaryConverter::BinaryConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::BinaryArray>(array))
{
}

PyObject* BinaryConverter::toPyObject(int64_t rowIndex) const
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
