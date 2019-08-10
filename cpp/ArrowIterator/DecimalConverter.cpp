/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include <string>

#include "DecimalConverter.hpp"
#include "Python/Helpers.hpp"

namespace sf
{

py::UniqueRef& DecimalBaseConverter::m_decimalConstructor()
{
    static py::UniqueRef decimalConstructor;
    if (decimalConstructor.empty())
    {
        py::PyUniqueLock lock;
        py::UniqueRef decimalModule;
        arrow::Status status = py::importPythonModule("decimal", decimalModule);

        status = py::importFromModule(decimalModule, "Decimal", decimalConstructor);
    }

    return decimalConstructor;
}

DecimalFromDecimalConverter::DecimalFromDecimalConverter(std::shared_ptr<arrow::Array> array, int scale)
    : m_array(std::dynamic_pointer_cast<arrow::Decimal128Array>(array)), m_scale(scale) {}


PyObject* DecimalFromDecimalConverter::toPyObject(int64_t rowIndex)
{
    if (m_array->IsValid(rowIndex))
    {
        std::string formatDecimalString = m_array->FormatValue(rowIndex);
        if (m_scale == 0)
        {
            return PyLong_FromString(formatDecimalString.c_str(), nullptr, 0);
        }

        /** the reason we use c_str() instead of std::string here is that we may meet some encoding problem with std::string */
        py::PyUniqueLock lock;
        return PyObject_CallFunction(m_decimalConstructor().get(), "s#", formatDecimalString.c_str(), formatDecimalString.size());
    }
    else
    {
        Py_RETURN_NONE;
    }
}

} // namespace sf
