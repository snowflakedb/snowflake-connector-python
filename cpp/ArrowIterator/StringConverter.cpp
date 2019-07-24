/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "StringConverter.hpp"

sf::StringConverter::StringConverter(arrow::Array * array)
{
    m_array = dynamic_cast<arrow::StringArray *>(array);
}

PyObject* sf::StringConverter::toPyObject(int64_t rowIndex)
{
    if (m_array->IsValid(rowIndex))
    {
        arrow::util::string_view sv = m_array->GetView(rowIndex);
        return PyUnicode_FromStringAndSize(sv.data(), sv.size());
    }
    else
    {
        return Py_None;
    }
}

