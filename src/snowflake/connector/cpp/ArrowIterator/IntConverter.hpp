//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_INTCONVERTER_HPP
#define PC_INTCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "nanoarrow.h"
#include "nanoarrow.hpp"
#include <memory>

namespace sf
{

template <typename T>
class IntConverter : public IColumnConverter
{
public:
  explicit IntConverter(ArrowArrayView* array)
  : m_array(array)
  {
  }

  PyObject* pyLongForward(int64_t value) const
  {
    return PyLong_FromLongLong(value);
  }

  PyObject* pyLongForward(int32_t value) const
  {
    return PyLong_FromLong(value);
  }

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  ArrowArrayView* m_array;
};

template <typename T>
PyObject* IntConverter<T>::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array, rowIndex);
  return pyLongForward(val);
}

template <typename T>
class NumpyIntConverter : public IColumnConverter
{
public:
  explicit NumpyIntConverter(ArrowArrayView* array, PyObject * context)
  : m_array(array),
    m_context(context)
  {
  }

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  ArrowArrayView* m_array;

  PyObject * m_context;
};

template <typename T>
PyObject* NumpyIntConverter<T>::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array, rowIndex)) {
      Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array, rowIndex);
  return PyObject_CallMethod(m_context, "FIXED_to_numpy_int64", "L", val);
}

}  // namespace sf

#endif  // PC_INTCONVERTER_HPP
