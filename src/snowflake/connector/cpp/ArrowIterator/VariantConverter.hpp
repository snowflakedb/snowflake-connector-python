//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_VARIANTCONVERTER_HPP
#define PC_VARIANTCONVERTER_HPP

#include "IColumnConverter.hpp"
#include "logging.hpp"
#include <memory>

namespace sf
{

class VariantConverter : public IColumnConverter
{
public:
  explicit VariantConverter(std::shared_ptr<arrow::Array> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

protected:
  py::UniqueRef& m_pyJsonLoader;
  py::UniqueRef& m_pySnowflakeJsonDecoder;

private:
  std::shared_ptr<arrow::StringArray> m_array;

  static Logger* logger;

  static py::UniqueRef& initPyJsonLoader();
  static py::UniqueRef& initPySnowflakeJsonDecoder();
};

}  // namespace sf

#endif  // PC_VARIANTCONVERTER_HPP
