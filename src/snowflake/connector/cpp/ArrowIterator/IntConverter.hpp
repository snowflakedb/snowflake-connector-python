//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_INTCONVERTER_HPP
#define PC_INTCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "nanoarrow.h"
#include <memory>

namespace sf
{

template <typename T>
class IntConverter : public IColumnConverter
{
public:
//  explicit IntConverter(std::shared_ptr<arrow::Array> array)
//  : m_array(std::dynamic_pointer_cast<T>(array))
//  {
//  }

  explicit IntConverter(std::shared_ptr<ArrowArrayView> array)
  : m_nanoarrowArrayView(array)
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
  std::shared_ptr<T> m_array;
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;
};

template <typename T>
PyObject* IntConverter<T>::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_nanoarrowArrayView.get(), rowIndex);
  return pyLongForward(val);
}

template <typename T>
class NumpyIntConverter : public IColumnConverter
{
public:
  explicit NumpyIntConverter(std::shared_ptr<arrow::Array> array, PyObject * context)
  : m_array(std::dynamic_pointer_cast<T>(array)),
    m_context(context)
  {
  }

  explicit NumpyIntConverter(std::shared_ptr<ArrowArrayView> array, PyObject * context)
  : m_nanoarrowArrayView(array),
    m_context(context)
  {
  }

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<T> m_array;
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  PyObject * m_context;
};

template <typename T>
PyObject* NumpyIntConverter<T>::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
      Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_nanoarrowArrayView.get(), rowIndex);
  return PyObject_CallMethod(m_context, "FIXED_to_numpy_int64", "L", val);
}

}  // namespace sf

#endif  // PC_INTCONVERTER_HPP
