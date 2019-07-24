/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "FloatConverter.hpp"

sf::FloatConverter::FloatConverter(arrow::Array* array)
{
    /** snowflake float is 64-precision, which refers to double here */
    m_array = dynamic_cast<arrow::DoubleArray*>(array);
}

PyObject* sf::FloatConverter::toPyObject(int64_t rowIndex)
{
    return (m_array->IsValid(rowIndex)) ? PyFloat_FromDouble(m_array->Value(rowIndex)) : Py_None;
}

