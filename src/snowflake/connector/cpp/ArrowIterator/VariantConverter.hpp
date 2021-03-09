//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#ifndef PC_VARIANTCONVERTER_HPP
#define PC_VARIANTCONVERTER_HPP

#include "IColumnConverter.hpp"

namespace sf
{

class VariantConverter : public IColumnConverter
{
public:
  explicit VariantConverter(std::shared_ptr<arrow::Array> array, PyObject* m_context);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<arrow::StringArray> m_array;

  PyObject* m_context;
};

}  // namespace sf

#endif  // PC_VARIANTCONVERTER_HPP
