/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_ICOLUMNCONVERTER_HPP
#define PC_ICOLUMNCONVERTER_HPP

#include <Python.h>
#include <arrow/python/platform.h>
#include <arrow/api.h>


namespace sf
{

class IColumnConverter
{
public:
    IColumnConverter() = default;
    virtual ~IColumnConverter() = default;
    virtual PyObject * toPyObject(int64_t rowIndex) = 0;
};

}


#endif // PC_ICOLUMNCONVERTER_HPP

