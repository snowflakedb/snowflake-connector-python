/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_BINARYCONVERTER_HPP
#define PC_BINARYCONVERTER_HPP

#include "IColumnConverter.hpp"

namespace sf
{

class BinaryConverter : public IColumnConverter
{
public:
  BinaryConverter(std::shared_ptr<arrow::Array> array);

  PyObject* toPyObject(int64_t rowIndex) override;

private:
  std::shared_ptr<arrow::BinaryArray> m_array;
};

}  // namespace sf

#endif  // PC_BINARYCONVERTER_HPP
