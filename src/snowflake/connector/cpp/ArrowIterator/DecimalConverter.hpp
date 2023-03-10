//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_DECIMALCONVERTER_HPP
#define PC_DECIMALCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "Python/Common.hpp"
#include "nanoarrow.h"
#include <memory>

namespace sf
{

class DecimalBaseConverter : public IColumnConverter
{
public:
  DecimalBaseConverter();
  virtual ~DecimalBaseConverter() = default;

protected:
  py::UniqueRef& m_pyDecimalConstructor;

private:
  static py::UniqueRef& initPyDecimalConstructor();
};

class DecimalFromDecimalConverter : public DecimalBaseConverter
{
public:
  explicit DecimalFromDecimalConverter(PyObject* context, std::shared_ptr<ArrowArrayView> array,
                                       int scale);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;
    PyObject* m_context;
  int m_scale;
  /** no need for this converter to store precision*/
};

template <typename T>
class DecimalFromIntConverter : public DecimalBaseConverter
{
public:
  explicit DecimalFromIntConverter(std::shared_ptr<ArrowArrayView> array,
                                   int precision, int scale)
  : m_nanoarrowArrayView(array),
    m_precision(precision),
    m_scale(scale)
  {
  }

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  int m_precision;  // looks like the precision here is not useful, and this
                    // will be removed soon when it's been confirmed

  int m_scale;
};

template <typename T>
PyObject* DecimalFromIntConverter<T>::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_nanoarrowArrayView.get(), rowIndex);
  py::UniqueRef decimal(
        PyObject_CallFunction(m_pyDecimalConstructor.get(), "L", val));
  return PyObject_CallMethod(decimal.get(), "scaleb", "i", -m_scale);
}


template <typename T>
class NumpyDecimalConverter : public IColumnConverter
{
public:
  explicit NumpyDecimalConverter(std::shared_ptr<ArrowArrayView> array,
                                 int precision, int scale, PyObject * context)
  : m_nanoarrowArrayView(array),
    m_precision(precision),
    m_scale(scale),
    m_context(context)
  {
  }

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  int m_precision;

  int m_scale;

  PyObject * m_context;
};

template <typename T>
PyObject* NumpyDecimalConverter<T>::toPyObject(int64_t rowIndex) const
{
    if(ArrowArrayViewIsNull(m_nanoarrowArrayView.get(), rowIndex)) {
        Py_RETURN_NONE;
    }
    int64_t val = ArrowArrayViewGetIntUnsafe(m_nanoarrowArrayView.get(), rowIndex);
    return PyObject_CallMethod(m_context, "FIXED_to_numpy_float64", "Li", val, m_scale);
}


}  // namespace sf

#endif  // PC_DECIMALCONVERTER_HPP
