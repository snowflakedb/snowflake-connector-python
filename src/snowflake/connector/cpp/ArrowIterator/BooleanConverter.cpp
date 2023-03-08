//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "BooleanConverter.hpp"
#include <memory>

namespace sf
{

BooleanConverter::BooleanConverter(std::shared_ptr<ArrowArrayView> array)
: m_nanoarrowArrayView(array)
{
}

PyObject* BooleanConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }

  if(ArrowArrayViewGetIntUnsafe(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
 }
}

}  // namespace sf
