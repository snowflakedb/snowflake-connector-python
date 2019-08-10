/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "DateConverter.hpp"
#include "Python/Helpers.hpp"
#include <iostream>

namespace sf
{

py::UniqueRef& DateConverter::m_pyDatetimeDate()
{
    static py::UniqueRef pyDatetimeDate;
    if (pyDatetimeDate.empty())
    {
        py::PyUniqueLock lock;
        py::UniqueRef pyDatetimeModule;
        arrow::Status status = py::importPythonModule("datetime", pyDatetimeModule);
        if (!status.ok())
        {
            /** cout is playing a placeholder here and will be replaced by exception soon */
            std::cout << "[ERROR] import python module 'datetime' failed" << std::endl;
        }
        status = py::importFromModule(pyDatetimeModule, "date", pyDatetimeDate);
        if (!status.ok())
        {
            /** cout is playing a placeholder here and will be replaced by exception soon */
            std::cout << "[ERROR] import python module 'datetime.date' failed" << std::endl;
        }
    }
    return pyDatetimeDate;
}

DateConverter::DateConverter(std::shared_ptr<arrow::Array> array)
    : m_array(std::dynamic_pointer_cast<arrow::Date32Array>(array)) {}

PyObject* DateConverter::toPyObject(int64_t rowIndex)
{
    if (m_array->IsValid(rowIndex))
    {
        int32_t deltaDays = m_array->Value(rowIndex);
        py::PyUniqueLock lock;
        return PyObject_CallMethod(m_pyDatetimeDate().get(), "fromordinal", "i", epochDay + deltaDays); 
    }
    else
    {
        Py_RETURN_NONE;
    }
}

} // namespace sf
