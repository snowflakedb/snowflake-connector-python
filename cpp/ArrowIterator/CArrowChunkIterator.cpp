/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "CArrowChunkIterator.hpp"
#include "IntConverter.hpp"
#include "StringConverter.hpp"

sf::CArrowChunkIterator::CArrowChunkIterator()
{
    this->reset();
}

void sf::CArrowChunkIterator::addRecordBatch(PyObject * rb)
{
    std::shared_ptr<arrow::RecordBatch> cRecordBatch;
    arrow::Status status = arrow::py::unwrap_record_batch(rb, &cRecordBatch);

    m_cRecordBatches.push_back(cRecordBatch);
    m_columnCount = m_cRecordBatches[0]->num_columns();
    m_batchCount = m_cRecordBatches.size();
}

void sf::CArrowChunkIterator::reset()
{
    m_currentBatchIndex = -1;
    m_rowIndexInBatch = -1;
    m_rowCountInBatch = 0;
}

PyObject * sf::CArrowChunkIterator::nextRow()
{
    m_rowIndexInBatch ++;

    if (m_rowIndexInBatch < m_rowCountInBatch)
    {
        return this->currentRowAsTuple();
    }
    else
    {
        m_currentBatchIndex ++;
        if (m_currentBatchIndex < m_batchCount)
        {
            m_rowIndexInBatch = 0;
            m_rowCountInBatch = m_cRecordBatches[m_currentBatchIndex]->num_rows();
            this->initColumnConverters();
            return this->currentRowAsTuple();
        }
    }

    return Py_None;
}

PyObject * sf::CArrowChunkIterator::currentRowAsTuple()
{
    PyObject* tuple = PyTuple_New(m_columnCount);
    for (int i = 0; i < m_columnCount; i++)
    {
        PyTuple_SET_ITEM(tuple, i, m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
    }
    return tuple;
}

void sf::CArrowChunkIterator::initColumnConverters()
{
    m_currentBatchConverters.clear();
    std::shared_ptr<arrow::RecordBatch> currentBatch = m_cRecordBatches[m_currentBatchIndex];
    std::shared_ptr<arrow::Schema> schema = currentBatch->schema();
    for (int i = 0; i < currentBatch->num_columns(); i++)
    {
        std::shared_ptr<arrow::Array> columnArray = currentBatch->column(i);
        std::shared_ptr<arrow::DataType> dt = schema->field(i)->type();
        switch(dt->id())
        {

            case arrow::Type::type::INT8:
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::Int8Converter>(columnArray.get()));
                break;

            case arrow::Type::type::INT16:
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::Int16Converter>(columnArray.get()));
                break;

            case arrow::Type::type::INT32:
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::Int32Converter>(columnArray.get()));
                break;

            case arrow::Type::type::INT64:
                m_currentBatchConverters.push_back(
                    std::make_shared<sf::Int64Converter>(columnArray.get()));
                break;

            case arrow::Type::type::STRING:
                m_currentBatchConverters.push_back(
                    std::make_shared<sf::StringConverter>(columnArray.get()));
                break;

            default:
                break;
        }
    }

}
