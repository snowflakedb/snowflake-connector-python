/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "CArrowChunkIterator.hpp"
#include "SnowflakeType.hpp"
#include "IntConverter.hpp"
#include "StringConverter.hpp"
#include "FloatConverter.hpp"
#include "DecimalConverter.hpp"
#include "BooleanConverter.hpp"
#include "DateConverter.hpp"
#include <iostream>

namespace sf
{

CArrowChunkIterator::CArrowChunkIterator() : m_latestReturnedRow(nullptr)
{
    this->reset();
}

void CArrowChunkIterator::addRecordBatch(PyObject * rb)
{
    std::shared_ptr<arrow::RecordBatch> cRecordBatch;
    arrow::Status status = arrow::py::unwrap_record_batch(rb, &cRecordBatch);

    m_cRecordBatches.push_back(cRecordBatch);
    m_columnCount = m_cRecordBatches[0]->num_columns();
    m_batchCount = m_cRecordBatches.size();
}

void CArrowChunkIterator::reset()
{
    m_currentBatchIndex = -1;
    m_rowIndexInBatch = -1;
    m_rowCountInBatch = 0;
    Py_XDECREF(m_latestReturnedRow);
    m_latestReturnedRow = nullptr;
}

PyObject * CArrowChunkIterator::nextRow()
{
    m_rowIndexInBatch ++;
    Py_XDECREF(m_latestReturnedRow);
    m_latestReturnedRow = nullptr;

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

    /** It looks like no one will decrease the ref of this Py_None, so we don't increament the ref count here */
    return Py_None;
}

PyObject * CArrowChunkIterator::currentRowAsTuple()
{
    PyObject* tuple = PyTuple_New(m_columnCount);
    for (int i = 0; i < m_columnCount; i++)
    {
        PyTuple_SET_ITEM(tuple, i, m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
    }
    return m_latestReturnedRow = tuple;
}

void CArrowChunkIterator::initColumnConverters()
{
    m_currentBatchConverters.clear();
    std::shared_ptr<arrow::RecordBatch> currentBatch = m_cRecordBatches[m_currentBatchIndex];
    std::shared_ptr<arrow::Schema> schema = currentBatch->schema();
    for (int i = 0; i < currentBatch->num_columns(); i++)
    {
        std::shared_ptr<arrow::Array> columnArray = currentBatch->column(i);
        std::shared_ptr<arrow::DataType> dt = schema->field(i)->type();
        std::shared_ptr<const arrow::KeyValueMetadata> metaData = schema->field(i)->metadata();
        SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
                                        metaData->value(metaData->FindKey("logicalType")));

        switch(st)
        {
            case SnowflakeType::Type::FIXED:
            {
                int scale = metaData ? std::stoi(metaData->value(metaData->FindKey("scale"))) : 0;
                int precision = metaData ? std::stoi(metaData->value(metaData->FindKey("precision"))) : 38;
                switch(dt->id())
                {

                    case arrow::Type::type::INT8:
                    {
                        if (scale > 0)
                        {
                            m_currentBatchConverters.push_back(
                                    std::make_shared<sf::DecimalFromIntConverter<arrow::Int8Array>>(
                                            columnArray,
                                            precision,
                                            scale));
                            break;
                        }

                        m_currentBatchConverters.push_back(
                                std::make_shared<sf::IntConverter<arrow::Int8Array>>(columnArray));
                        break;
                    }

                    case arrow::Type::type::INT16:
                    {
                        if (scale > 0)
                        {
                            m_currentBatchConverters.push_back(
                                    std::make_shared<sf::DecimalFromIntConverter<arrow::Int16Array>>(
                                            columnArray,
                                            precision,
                                            scale));
                            break;
                        }

                        m_currentBatchConverters.push_back(
                                std::make_shared<sf::IntConverter<arrow::Int16Array>>(columnArray));
                        break;
                    }

                    case arrow::Type::type::INT32:
                    {
                        if (scale > 0)
                        {
                            m_currentBatchConverters.push_back(
                                    std::make_shared<sf::DecimalFromIntConverter<arrow::Int32Array>>(
                                            columnArray,
                                            precision,
                                            scale));
                            break;
                        }

                        m_currentBatchConverters.push_back(
                                std::make_shared<sf::IntConverter<arrow::Int32Array>>(columnArray));
                        break;
                    }

                    case arrow::Type::type::INT64:
                    {
                        if (scale > 0)
                        {
                            m_currentBatchConverters.push_back(
                                    std::make_shared<sf::DecimalFromIntConverter<arrow::Int64Array>>(
                                            columnArray,
                                            precision,
                                            scale));
                            break;
                        }

                        m_currentBatchConverters.push_back(
                                std::make_shared<sf::IntConverter<arrow::Int64Array>>(columnArray));
                        break;
                    }

                    case arrow::Type::type::DECIMAL:
                    {
                        m_currentBatchConverters.push_back(
                                std::make_shared<sf::DecimalFromDecimalConverter>(columnArray, scale));
                        break;
                    }

                    default:
                    {
                        /** cout is playing a placeholder here and will be replaced by exception soon */
                        std::cout << "unknown arrow internal data type (" << dt->id() << ") for FIXED data" << std::endl;
                        break;
                    }
                }
                break;
            }

            case SnowflakeType::Type::TEXT:
            {
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::StringConverter>(columnArray));
                break;
            }
            
            case SnowflakeType::Type::BOOLEAN:
            {
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::BooleanConverter>(columnArray));
                break;
            }
            
            case SnowflakeType::Type::REAL:
            {
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::FloatConverter>(columnArray));
                break;
            }

            case SnowflakeType::Type::DATE:
            {
                m_currentBatchConverters.push_back(
                        std::make_shared<sf::DateConverter>(columnArray));
                break;
            }

            default:
            {
                /** cout is playing a placeholder here and will be replaced by exception soon */
                std::cout << "[ERROR] unknown snowflake data type : " << metaData->value(metaData->FindKey("logicalType")) << std::endl;
                break;
            }
        }    
    }

}

} // namespace sf
