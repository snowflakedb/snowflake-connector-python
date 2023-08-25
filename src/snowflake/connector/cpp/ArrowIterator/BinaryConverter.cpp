//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "BinaryConverter.hpp"
#include <memory>
#include <iostream>
using namespace std;

namespace sf
{
Logger* BinaryConverter::logger = new Logger("snowflake.connector.BinaryConverter");

BinaryConverter::BinaryConverter(ArrowArrayView* array)
: m_array(array)
{
}

PyObject* BinaryConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  cout << "I am trying to get string in byte converter" << endl;
  ArrowStringView stringView = ArrowArrayViewGetStringUnsafe(m_array, rowIndex);
  cout << "I finishing getting string in byte converter" << endl;
  return PyByteArray_FromStringAndSize(stringView.data, stringView.size_bytes);
}

}  // namespace sf
