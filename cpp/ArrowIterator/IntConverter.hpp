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

    PyObject * toPyObject(long rowIndex) override;

private:
    arrow::Int64Array * m_array;
};

}

#endif
