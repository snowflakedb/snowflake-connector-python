//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_BINARYCONVERTER_HPP
#define PC_BINARYCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "logging.hpp"
#include <memory>
#include "nanoarrow.h"

namespace sf
{

class BinaryConverter : public IColumnConverter
{
public:
  explicit BinaryConverter(std::shared_ptr<ArrowArrayView> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_array;

  static Logger* logger;
};

}  // namespace sf

#endif  // PC_BINARYCONVERTER_HPP
