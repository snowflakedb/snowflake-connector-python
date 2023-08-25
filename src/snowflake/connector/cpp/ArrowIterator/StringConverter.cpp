//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "StringConverter.hpp"
#include <memory>
#include <iostream>
using namespace std;

namespace sf
{
Logger* StringConverter::logger = new Logger("snowflake.connector.StringConverter");

StringConverter::StringConverter(ArrowArrayView* array)
: m_array(array)
{
}

PyObject* StringConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  cout << "I am trying to get string in string converter" << endl;
  ArrowStringView stringView = ArrowArrayViewGetStringUnsafe(m_array, rowIndex);
  cout << "I finishing getting string in string converter" << endl;
  return PyUnicode_FromStringAndSize(stringView.data, stringView.size_bytes);
}

}  // namespace sf
