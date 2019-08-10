/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_DATECONVERTER_HPP
#define PC_DATECONVERTER_HPP

#include "IColumnConverter.hpp"
#include "Python/Common.hpp"

namespace sf
{

class DateConverter : public IColumnConverter
{
public:
    DateConverter(std::shared_ptr<arrow::Array> array);

    PyObject* toPyObject(int64_t rowIndex) override;

private:
    std::shared_ptr<arrow::Date32Array> m_array;

    /** from Python Ordinal to 1970-01-01 */
    static constexpr int epochDay = 719163;

    static py::UniqueRef& m_pyDatetimeDate();
};

} // namespace sf

#endif // PC_DATECONVERTER_HPP
