//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "FloatConverter.hpp"
#include <memory>

namespace sf
{

/** snowflake float is 64-precision, which refers to double here */
FloatConverter::FloatConverter(std::shared_ptr<ArrowArrayView> array)
: m_nanoarrowArrayView(array)
{
}

PyObject* FloatConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  return PyFloat_FromDouble(ArrowArrayViewGetDoubleUnsafe(m_nanoarrowArrayView.get(), rowIndex));
}

NumpyFloat64Converter::NumpyFloat64Converter(std::shared_ptr<ArrowArrayView> array, PyObject * context)
: m_nanoarrowArrayView(array), m_context(context)
{
}

PyObject* NumpyFloat64Converter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }

  double val = ArrowArrayViewGetDoubleUnsafe(m_nanoarrowArrayView.get(), rowIndex);
  return PyObject_CallMethod(m_context, "REAL_to_numpy_float64", "d", val);

}

}  // namespace sf
