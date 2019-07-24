/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_INTCONVERTER_HPP
#define PC_INTCONVERTER_HPP

#include "IColumnConverter.hpp"

namespace sf
{

class Int64Converter : public IColumnConverter
{
public:
    Int64Converter(arrow::Array * array);

    PyObject * toPyObject(int64_t rowIndex) override;

private:
    arrow::Int64Array * m_array;
};

class Int32Converter : public IColumnConverter
{
public:
    Int32Converter(arrow::Array * array);

    PyObject * toPyObject(int64_t rowIndex) override;

private:
    arrow::Int32Array * m_array;
};

class Int16Converter : public IColumnConverter
{
public:
    Int16Converter(arrow::Array * array);

    PyObject * toPyObject(int64_t rowIndex) override;

private:
    arrow::Int16Array * m_array;
};

class Int8Converter : public IColumnConverter
{
public:
    Int8Converter(arrow::Array * array);

    PyObject * toPyObject(int64_t rowIndex) override;

private:
    arrow::Int8Array * m_array;
};

}

#endif
