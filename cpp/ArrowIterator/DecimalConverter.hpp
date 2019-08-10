/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_DECIMALCONVERTER_HPP
#define PC_DECIMALCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "Python/Common.hpp"

namespace sf
{

class DecimalBaseConverter : public IColumnConverter
{
public:
  DecimalBaseConverter() = default;
  virtual ~DecimalBaseConverter() = default;

protected:
  static py::UniqueRef& m_decimalConstructor();
};

class DecimalFromDecimalConverter : public DecimalBaseConverter
{
public:
  DecimalFromDecimalConverter(std::shared_ptr<arrow::Array> array, int scale);

  PyObject* toPyObject(int64_t rowIndex) override;

private:
  std::shared_ptr<arrow::Decimal128Array> m_array;

  int m_scale;
  /** no need for this converter to store precision*/
};

template <typename T>
class DecimalFromIntConverter : public DecimalBaseConverter
{
public:
  DecimalFromIntConverter(std::shared_ptr<arrow::Array> array, int precision,
                          int scale)
  : m_array(std::dynamic_pointer_cast<T>(array)),
    m_precision(precision),
    m_scale(scale)
  {
  }

  PyObject* toPyObject(int64_t rowIndex) override;

private:
  std::shared_ptr<T> m_array;

  int m_precision;  // looks like the precision here is not useful, and this
                    // will be removed soon when it's been confirmed

  int m_scale;
};

template <typename T>
PyObject* DecimalFromIntConverter<T>::toPyObject(int64_t rowIndex)
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t val = m_array->Value(rowIndex);

    py::UniqueRef decimal(
        PyObject_CallFunction(m_decimalConstructor().get(), "L", val));
    return PyObject_CallMethod(decimal.get(), "scaleb", "i", -m_scale);
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf

#endif  // PC_DECIMALCONVERTER_HPP
