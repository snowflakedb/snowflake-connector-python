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

sf::Int32Converter::Int32Converter(arrow::Array *array)
{
    m_array = dynamic_cast<arrow::Int32Array *>(array);
}

PyObject* sf::Int32Converter::toPyObject(int64_t rowIndex)
{
    return (m_array->IsValid(rowIndex)) ? PyLong_FromLong(m_array->Value(rowIndex)) : Py_None;
}


sf::Int16Converter::Int16Converter(arrow::Array *array)
{
    m_array = dynamic_cast<arrow::Int16Array *>(array);
}

PyObject* sf::Int16Converter::toPyObject(int64_t rowIndex)
{
    return (m_array->IsValid(rowIndex)) ? PyLong_FromLong(m_array->Value(rowIndex)) : Py_None;
}

sf::Int8Converter::Int8Converter(arrow::Array *array)
{
    m_array = dynamic_cast<arrow::Int8Array *>(array);
}

PyObject* sf::Int8Converter::toPyObject(int64_t rowIndex)
{
    return (m_array->IsValid(rowIndex)) ? PyLong_FromLong(m_array->Value(rowIndex)) : Py_None;
}


