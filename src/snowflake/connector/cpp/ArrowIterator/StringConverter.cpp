//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "StringConverter.hpp"
#include <memory>

namespace sf
{
Logger* StringConverter::logger = new Logger("snowflake.connector.StringConverter");

StringConverter::StringConverter(std::shared_ptr<ArrowArrayView> array)
: m_nanoarrowArrayView(array)
{
}

StringConverter::StringConverter(ArrowArrayView* array)
: m_uniqueArray(array)
{
}

PyObject* StringConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  ArrowStringView stringView = ArrowArrayViewGetStringUnsafe(m_nanoarrowArrayView.get(), rowIndex);
  return PyUnicode_FromStringAndSize(stringView.data, stringView.size_bytes);
}

}  // namespace sf
