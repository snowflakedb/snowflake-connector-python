//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_BOOLEANCONVERTER_HPP
#define PC_BOOLEANCONVERTER_HPP

#include "IColumnConverter.hpp"
#include <memory>
#include "nanoarrow.h"

namespace sf
{

class BooleanConverter : public IColumnConverter
{
public:
  explicit BooleanConverter(ArrowArrayView* array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  ArrowArrayView* m_array;
};

}  // namespace sf

#endif  // PC_BOOLEANCONVERTER_HPP
