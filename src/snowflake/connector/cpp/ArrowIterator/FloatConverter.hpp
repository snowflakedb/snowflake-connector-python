//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_FLOATCONVERTER_HPP
#define PC_FLOATCONVERTER_HPP

#include "IColumnConverter.hpp"
#include <memory>
#include "nanoarrow.h"

namespace sf
{

class FloatConverter : public IColumnConverter
{
public:
  explicit FloatConverter(std::shared_ptr<ArrowArrayView> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;
};

class NumpyFloat64Converter : public IColumnConverter
{
public:
  explicit NumpyFloat64Converter(std::shared_ptr<ArrowArrayView> array, PyObject * context);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  PyObject * m_context;
};

}  // namespace sf

#endif  // PC_FLOATCONVERTER_HPP
