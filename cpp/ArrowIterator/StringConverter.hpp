/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_STRINGCONVERTER_HPP
#define PC_STRINGCONVERTER_HPP

#include "IColumnConverter.hpp"

namespace sf
{

class StringConverter : public IColumnConverter
{
public:
    StringConverter(std::shared_ptr<arrow::Array> array);

    PyObject* toPyObject(int64_t rowIndex) override;

private:
    std::shared_ptr<arrow::StringArray> m_array;
};

} // namespace sf

#endif // PC_STRINGCONVERTER_HPP
