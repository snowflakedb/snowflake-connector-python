/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "CArrowTableIterator.hpp"
#include "SnowflakeType.hpp"
#include <string>

namespace sf
{

CArrowTableIterator::CArrowTableIterator(PyObject* context)
: m_context(context)
{
}

void CArrowTableIterator::addRecordBatch(PyObject* rb)
{
  // may add some specific behaviors for this iterator
  // e.g. support retrieve table with row size
  CArrowIterator::addRecordBatch(rb);
}

void CArrowTableIterator::reset()
{
}

PyObject* CArrowTableIterator::next()
{
  bool firstDone = this->convertRecordBatchesToTable();
  return (firstDone && m_cTable) ? arrow::py::wrap_table(m_cTable) : Py_None;
}

void CArrowTableIterator::reconstructRecordBatches()
{
  // TODO: type conversion, the code needs to be optimized
  for (unsigned int batchIdx = 0; batchIdx <  m_cRecordBatches.size(); batchIdx++)
  {
    std::shared_ptr<arrow::RecordBatch> currentBatch = m_cRecordBatches[batchIdx];
    std::shared_ptr<arrow::Schema> schema = currentBatch->schema();
    for (int colIdx = 0; colIdx < currentBatch->num_columns(); colIdx++)
    {
      std::shared_ptr<arrow::Array> columnArray = currentBatch->column(colIdx);
      std::shared_ptr<arrow::DataType> dt = schema->field(colIdx)->type();
      std::shared_ptr<const arrow::KeyValueMetadata> metaData =
          schema->field(colIdx)->metadata();
      SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
          metaData->value(metaData->FindKey("logicalType")));
      // TODO: reconstruct columnArray in place, use method like
      // columnArray->SetData(const std::shared_ptr<ArrayData>& data)
      switch (st)
      {
        case SnowflakeType::Type::FIXED:
        {
          int scale = metaData
                          ? std::stoi(metaData->value(metaData->FindKey("scale")))
                          : 0;
//            int precision =
//                metaData
//                    ? std::stoi(metaData->value(metaData->FindKey("precision")))
//                    : 38;
          switch (dt->id())
          {

            case arrow::Type::type::INT8:
            {
              if (scale > 0)
              {
                // TODO: convert to arrow float64
              }

              // Do nothing if scale = 0, but may have edge case
              break;
            }

            case arrow::Type::type::INT16:
            {
              if (scale > 0)
              {
                // TODO: convert to arrow float64
              }

              // Do nothing if scale = 0, but may have edge case
              break;
            }

            case arrow::Type::type::INT32:
            {
              if (scale > 0)
              {
                // TODO: convert to arrow float64
              }

              // Do nothing if scale = 0, but may have edge case
              break;
            }

            case arrow::Type::type::INT64:
            {
              if (scale > 0)
              {
                // TODO: convert to arrow float64
              }

              // Do nothing if scale = 0, but may have edge case
              break;
            }

            case arrow::Type::type::DECIMAL:
            {
              // TODO: convert to arrow float64
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
        case SnowflakeType::Type::BINARY:
        case SnowflakeType::Type::VARIANT:
        case SnowflakeType::Type::TEXT:
        {
          // TODO: convert to arrow string (utf8)
          break;
        }

        case SnowflakeType::Type::BOOLEAN:
        {
          //  Do nothing
          break;
        }

        case SnowflakeType::Type::REAL:
        {
          // TODO: convert to arrow float64
          break;
        }

        case SnowflakeType::Type::DATE:
        {
          // TODO: convert to arrow dateDay
          break;
        }

        case SnowflakeType::Type::TIME:
        {
//            int scale = metaData
//                            ? std::stoi(metaData->value(metaData->FindKey("scale")))
//                            : 9;
          switch (dt->id())
          {
            case arrow::Type::type::INT32:
            {
              // TODO: convert to arrow timestamp
              break;
            }

            case arrow::Type::type::INT64:
            {
              // TODO: convert to arrow timestamp
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
//            int scale = metaData
//                            ? std::stoi(metaData->value(metaData->FindKey("scale")))
//                            : 9;
          switch (dt->id())
          {
            case arrow::Type::type::INT64:
            {
              // TODO: convert to arrow timestamp
              break;
            }

            case arrow::Type::type::STRUCT:
            {
              // TODO: convert to arrow timestamp
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
//            int scale = metaData
//                            ? std::stoi(metaData->value(metaData->FindKey("scale")))
//                            : 9;
          switch (dt->id())
          {
            case arrow::Type::type::INT64:
            {
              // TODO: convert to arrow timestamp
              break;
            }

            case arrow::Type::type::STRUCT:
            {
             // TODO: convert to arrow timestamp
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
          // int scale = metaData
          //                 ? std::stoi(metaData->value(metaData->FindKey("scale")))
          //                 : 9;
          int byteLength =
              metaData
                  ? std::stoi(metaData->value(metaData->FindKey("byteLength")))
                  : 16;
          switch (byteLength)
          {
            case 8:
            {
              // TODO: convert to arrow timestamp
              break;
            }

            case 16:
            {
              // TODO: convert to arrow timestamp
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
}

bool CArrowTableIterator::convertRecordBatchesToTable()
{
  // only do conversion once and there exist some record batches
  if (!m_cTable && !m_cRecordBatches.empty())
  {
    reconstructRecordBatches();
    arrow::Table::FromRecordBatches(m_cRecordBatches, &m_cTable);
    return true;
  }
  return false;
}

} // namespace sf
