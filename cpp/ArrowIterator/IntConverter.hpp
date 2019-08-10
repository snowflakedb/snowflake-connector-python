/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_INTCONVERTER_HPP
#define PC_INTCONVERTER_HPP

#include "IColumnConverter.hpp"
#include <iostream>

namespace sf
{

template <typename T>
class IntConverter : public IColumnConverter
{
public:
  explicit IntConverter(std::shared_ptr<arrow::Array> array)
  : m_array(std::dynamic_pointer_cast<T>(array))
  {
  }

  PyObject* pyLongForward(int64_t value)
  {
    return PyLong_FromLongLong(value);
  }

  PyObject* pyLongForward(int32_t value)
  {
    return PyLong_FromLong(value);
  }

  PyObject* toPyObject(int64_t rowIndex) override;

private:
  std::shared_ptr<T> m_array;
};

template <typename T>
PyObject* IntConverter<T>::toPyObject(int64_t rowIndex)
{
  if (m_array->IsValid(rowIndex))
  {
    // TODO : this forward function need to be tested in Win64
    return pyLongForward(m_array->Value(rowIndex));
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf

#endif  // PC_INTCONVERTER_HPP
