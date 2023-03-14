//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_STRINGCONVERTER_HPP
#define PC_STRINGCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "logging.hpp"
#include <memory>
#include "nanoarrow.h"
#include "nanoarrow.hpp"

namespace sf
{

class StringConverter : public IColumnConverter
{
public:
  explicit StringConverter(std::shared_ptr<ArrowArrayView> array);
  explicit StringConverter(ArrowArrayView* array);
  explicit StringConverter(nanoarrow::UniqueArrayView array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;
  ArrowArrayView* m_uniqueArray;

  static Logger* logger;
};

}  // namespace sf

#endif  // PC_STRINGCONVERTER_HPP
