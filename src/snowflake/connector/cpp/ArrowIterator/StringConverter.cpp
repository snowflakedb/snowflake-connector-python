//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "StringConverter.hpp"
#include <memory>

namespace sf
{
Logger* StringConverter::logger = new Logger("snowflake.connector.StringConverter");

StringConverter::StringConverter(std::shared_ptr<arrow::Array> array)
: m_array(std::dynamic_pointer_cast<arrow::StringArray>(array))
{
}

PyObject* StringConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    std::string_view sv = m_array->GetView(rowIndex);
    return PyUnicode_FromStringAndSize(sv.data(), sv.size());
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
