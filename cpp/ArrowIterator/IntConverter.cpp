/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "IntConverter.hpp"

sf::Int64Converter::Int64Converter(arrow::Array *array)
{
    m_array = dynamic_cast<arrow::Int64Array *>(array);
}

PyObject* sf::Int64Converter::toPyObject(int64_t rowIndex)
{
    return (m_array->IsValid(rowIndex)) ? PyLong_FromLong(m_array->Value(rowIndex)) : Py_None;
}

