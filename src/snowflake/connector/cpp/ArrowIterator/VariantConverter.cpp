//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#include "VariantConverter.hpp"
#include "Python/Helpers.hpp"
#include <memory>

namespace sf
{
Logger* VariantConverter::logger = new Logger("snowflake.connector.VariantConverter");

VariantConverter::VariantConverter(std::shared_ptr<arrow::Array> array) :
m_array(std::dynamic_pointer_cast<arrow::StringArray>(array)),
m_pyJsonLoader(initPyJsonLoader()),
m_pySnowflakeJsonDecoder(initPySnowflakeJsonDecoder())
{
}

py::UniqueRef& VariantConverter::initPyJsonLoader()
{
  static py::UniqueRef pyJsonLoader;
  if (pyJsonLoader.empty())
  {
    py::UniqueRef jsonModule;
    py::importPythonModule("json", jsonModule);
    py::importFromModule(jsonModule, "loads", pyJsonLoader);
    Py_XINCREF(pyJsonLoader.get());
  }

  return pyJsonLoader;
}

py::UniqueRef& VariantConverter::initPySnowflakeJsonDecoder()
{
  static py::UniqueRef pySnowflakeJsonDecoder;
  if (pySnowflakeJsonDecoder.empty())
  {
    py::UniqueRef jsonDecoderModule;
    py::importPythonModule("snowflake.connector.json_decoder", jsonDecoderModule);
    py::importFromModule(jsonDecoderModule, "SnowflakeJSONDecoder", pySnowflakeJsonDecoder);
    Py_XINCREF(pySnowflakeJsonDecoder.get());
  }

  return pySnowflakeJsonDecoder;
}

PyObject* VariantConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    arrow::util::string_view sv = m_array->GetView(rowIndex);
    py::UniqueRef kwargs(PyDict_New());
    PyDict_SetItemString(kwargs.get(), "cls", m_pySnowflakeJsonDecoder.get());

    return PyObject_Call(m_pyJsonLoader.get(),
                         Py_BuildValue("(s#)", sv.data(), static_cast<Py_ssize_t>(sv.size())),
                         kwargs.get());
  }
  else
  {
    Py_RETURN_NONE;
  }
}

}  // namespace sf
