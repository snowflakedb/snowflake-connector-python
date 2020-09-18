//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#ifndef PC_BINARYCONVERTER_HPP
#define PC_BINARYCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "logging.hpp"

namespace sf
{

class BinaryConverter : public IColumnConverter
{
public:
  explicit BinaryConverter(std::shared_ptr<arrow::Array> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<arrow::BinaryArray> m_array;

  static Logger* logger;
};

}  // namespace sf

#endif  // PC_BINARYCONVERTER_HPP
