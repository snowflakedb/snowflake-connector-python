/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_FLOATCONVERTER_HPP
#define PC_FLOATCONVERTER_HPP

#include "IColumnConverter.hpp"

namespace sf
{

class FloatConverter : public IColumnConverter
{
public:
    explicit FloatConverter(arrow::Array* array);

    PyObject* toPyObject(int64_t rowIndex) override;

private:
    arrow::DoubleArray* m_array;
};
}

#endif
