/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "CArrowChunkIterator.hpp"
#include "SnowflakeType.hpp"
#include "IntConverter.hpp"
#include "StringConverter.hpp"
#include "FloatConverter.hpp"
#include "DecimalConverter.hpp"
#include "BinaryConverter.hpp"
#include "BooleanConverter.hpp"
#include "DateConverter.hpp"
#include "TimeStampConverter.hpp"
#include "TimeConverter.hpp"
#include <string>

namespace sf
{

CArrowChunkIterator::CArrowChunkIterator(PyObject* context, std::vector<std::shared_ptr<arrow::RecordBatch>> *batches)
: CArrowIterator(batches), m_latestReturnedRow(nullptr), m_context(context)
{
  m_batchCount = m_cRecordBatches->size();
  m_columnCount = m_batchCount > 0 ? (*m_cRecordBatches)[0]->num_columns() : 0;
  m_currentBatchIndex = -1;
  m_rowIndexInBatch = -1;
  m_rowCountInBatch = 0;
  m_latestReturnedRow.reset();

  logger.debug("Arrow chunk info: batchCount %d, columnCount %d", m_batchCount,
               m_columnCount);
}

PyObject* CArrowChunkIterator::next()
{
  m_rowIndexInBatch++;

  if (m_rowIndexInBatch < m_rowCountInBatch)
  {
    this->currentRowAsTuple();
    if (py::checkPyError())
    {
      return nullptr;
    }
    return m_latestReturnedRow.get();
  }
  else
  {
    m_currentBatchIndex++;
    if (m_currentBatchIndex < m_batchCount)
    {
      m_rowIndexInBatch = 0;
      m_rowCountInBatch = (*m_cRecordBatches)[m_currentBatchIndex]->num_rows();
      this->initColumnConverters();
      if (py::checkPyError())
      {
        return nullptr;
      }

      logger.debug("Current batch index: %d, rows in current batch: %d",
                  m_currentBatchIndex, m_rowCountInBatch);

      this->currentRowAsTuple();
      if (py::checkPyError())
      {
        return nullptr;
      }
      return m_latestReturnedRow.get();
    }
  }

  /** It looks like no one will decrease the ref of this Py_None, so we don't
   * increament the ref count here */
  return Py_None;
}

void CArrowChunkIterator::currentRowAsTuple()
{
  m_latestReturnedRow.reset(PyTuple_New(m_columnCount));
  for (int i = 0; i < m_columnCount; i++)
  {
    PyTuple_SET_ITEM(
        m_latestReturnedRow.get(), i,
        m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
  }
  return;
}

void CArrowChunkIterator::initColumnConverters()
{
  m_currentBatchConverters.clear();
  std::shared_ptr<arrow::RecordBatch> currentBatch =
      (*m_cRecordBatches)[m_currentBatchIndex];
  std::shared_ptr<arrow::Schema> schema = currentBatch->schema();
  for (int i = 0; i < currentBatch->num_columns(); i++)
  {
    std::shared_ptr<arrow::Array> columnArray = currentBatch->column(i);
    std::shared_ptr<arrow::DataType> dt = schema->field(i)->type();
    std::shared_ptr<const arrow::KeyValueMetadata> metaData =
        schema->field(i)->metadata();
    SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
        metaData->value(metaData->FindKey("logicalType")));

    switch (st)
    {
      case SnowflakeType::Type::FIXED:
      {
        int scale = metaData
                        ? std::stoi(metaData->value(metaData->FindKey("scale")))
                        : 0;
        int precision =
            metaData
                ? std::stoi(metaData->value(metaData->FindKey("precision")))
                : 38;
        switch (dt->id())
        {

          case arrow::Type::type::INT8:
          {
            if (scale > 0)
            {
              m_currentBatchConverters.push_back(std::make_shared<
                  sf::DecimalFromIntConverter<arrow::Int8Array>>(
                  columnArray, precision, scale));
              break;
            }

            m_currentBatchConverters.push_back(
                std::make_shared<sf::IntConverter<arrow::Int8Array>>(
                    columnArray));
            break;
          }

          case arrow::Type::type::INT16:
          {
            if (scale > 0)
            {
              m_currentBatchConverters.push_back(std::make_shared<
                  sf::DecimalFromIntConverter<arrow::Int16Array>>(
                  columnArray, precision, scale));
              break;
            }

            m_currentBatchConverters.push_back(
                std::make_shared<sf::IntConverter<arrow::Int16Array>>(
                    columnArray));
            break;
          }

          case arrow::Type::type::INT32:
          {
            if (scale > 0)
            {
              m_currentBatchConverters.push_back(std::make_shared<
                  sf::DecimalFromIntConverter<arrow::Int32Array>>(
                  columnArray, precision, scale));
              break;
            }

            m_currentBatchConverters.push_back(
                std::make_shared<sf::IntConverter<arrow::Int32Array>>(
                    columnArray));
            break;
          }

          case arrow::Type::type::INT64:
          {
            if (scale > 0)
            {
              m_currentBatchConverters.push_back(std::make_shared<
                  sf::DecimalFromIntConverter<arrow::Int64Array>>(
                  columnArray, precision, scale));
              break;
            }

            m_currentBatchConverters.push_back(
                std::make_shared<sf::IntConverter<arrow::Int64Array>>(
                    columnArray));
            break;
          }

          case arrow::Type::type::DECIMAL:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::DecimalFromDecimalConverter>(columnArray,
                                                                  scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                dt->id());
            logger.error(errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::ANY:
      case SnowflakeType::Type::CHAR:
      case SnowflakeType::Type::OBJECT:
      case SnowflakeType::Type::VARIANT:
      case SnowflakeType::Type::TEXT:
      case SnowflakeType::Type::ARRAY:
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

      case SnowflakeType::Type::BINARY:
      {
        m_currentBatchConverters.push_back(
            std::make_shared<sf::BinaryConverter>(columnArray));
        break;
      }

      case SnowflakeType::Type::TIME:
      {
        int scale = metaData
                        ? std::stoi(metaData->value(metaData->FindKey("scale")))
                        : 9;
        switch (dt->id())
        {
          case arrow::Type::type::INT32:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TimeConverter<arrow::Int32Array>>(
                    columnArray, scale));
            break;
          }

          case arrow::Type::type::INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TimeConverter<arrow::Int64Array>>(
                    columnArray, scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIME data",
                dt->id());
            logger.error(errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_NTZ:
      {
        int scale = metaData
                        ? std::stoi(metaData->value(metaData->FindKey("scale")))
                        : 9;
        switch (dt->id())
        {
          case arrow::Type::type::INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::OneFieldTimeStampNTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          case arrow::Type::type::STRUCT:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampNTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_NTZ data",
                dt->id());
            logger.error(errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_LTZ:
      {
        int scale = metaData
                        ? std::stoi(metaData->value(metaData->FindKey("scale")))
                        : 9;
        switch (dt->id())
        {
          case arrow::Type::type::INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::OneFieldTimeStampLTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          case arrow::Type::type::STRUCT:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampLTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_LTZ data",
                dt->id());
            logger.error(errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_TZ:
      {
        int scale = metaData
                        ? std::stoi(metaData->value(metaData->FindKey("scale")))
                        : 9;
        int byteLength =
            metaData
                ? std::stoi(metaData->value(metaData->FindKey("byteLength")))
                : 16;
        switch (byteLength)
        {
          case 8:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          case 16:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::ThreeFieldTimeStampTZConverter>(
                    columnArray, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_TZ data",
                dt->id());
            logger.error(errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }

        break;
      }

      default:
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] unknown snowflake data type : %s",
            metaData->value(metaData->FindKey("logicalType")).c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }
  }
}

}  // namespace sf
