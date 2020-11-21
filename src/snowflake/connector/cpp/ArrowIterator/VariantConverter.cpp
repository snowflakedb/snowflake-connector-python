//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#include "VariantConverter.hpp"

namespace sf
{

VariantConverter::VariantConverter(std::shared_ptr<arrow::Array> array, PyObject* context)
: m_array(std::dynamic_pointer_cast<arrow::StringArray>(array)), m_context(context)
{
}

PyObject* VariantConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    arrow::util::string_view sv = m_array->GetView(rowIndex);
    PyObject* string = PyUnicode_FromStringAndSize(sv.data(), sv.size());

    return PyObject_CallMethod(m_context, "VARIANT_to_python",
                               "O", string);
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
