//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_STRINGCONVERTER_HPP
#define PC_STRINGCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "logging.hpp"
#include <memory>
#include "nanoarrow.h"

namespace sf
{

class StringConverter : public IColumnConverter
{
public:
  explicit StringConverter(std::shared_ptr<ArrowArrayView> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  static Logger* logger;
};

}  // namespace sf

#endif  // PC_STRINGCONVERTER_HPP
