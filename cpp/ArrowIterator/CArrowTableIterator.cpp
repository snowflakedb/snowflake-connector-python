/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "CArrowTableIterator.hpp"
#include "SnowflakeType.hpp"
#include "Util/time.hpp"
#include <string>

namespace sf
{

/**
 * This function is to make sure the arrow table can be successfully converted to pandas dataframe
 * using arrow's to_pandas method. Since some Snowflake arrow columns are not supported, this method
 * can map those to supported ones.
 * Specifically,
 *    All Snowflake fixed number with scale > 0 (expect decimal) will be converted to Arrow float64/double column
 *    All Snowflake time columns will be converted to Arrow Time column with unit = second, milli, or, micro.
 *    All Snowflake timestamp columns will be converted to Arrow timestamp columns
 *    Specifically,
 *    timestampntz will be converted to Arrow timestamp with UTC
 *    timestampltz will be converted to Arrow timestamp with session time zone
 *    timestamptz will be converted to Arrow timestamp with UTC
 *    Since Arrow timestamp use int64_t internally so it may be out of range for small and large timestamps
 */
void CArrowTableIterator::reconstructRecordBatches()
{
  // Type conversion, the code needs to be optimized
  for (unsigned int batchIdx = 0; batchIdx <  m_cRecordBatches.size(); batchIdx++)
  {
    std::shared_ptr<arrow::RecordBatch> currentBatch = m_cRecordBatches[batchIdx];
    std::shared_ptr<arrow::Schema> schema = currentBatch->schema();
    for (int colIdx = 0; colIdx < currentBatch->num_columns(); colIdx++)
    {
      std::shared_ptr<arrow::Array> columnArray = currentBatch->column(colIdx);
      std::shared_ptr<arrow::Field> field = schema->field(colIdx);
      std::shared_ptr<arrow::DataType> dt = field->type();
      std::shared_ptr<const arrow::KeyValueMetadata> metaData = field->metadata();
      SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
          metaData->value(metaData->FindKey("logicalType")));

      // reconstruct columnArray in place
      switch (st)
      {
        case SnowflakeType::Type::FIXED:
        {
          int scale = metaData
                          ? std::stoi(metaData->value(metaData->FindKey("scale")))
                          : 0;
          if (scale > 0 && dt->id() != arrow::Type::type::DECIMAL)
          {
            convertScaledFixedNumberColumnToDoubleColumn(batchIdx, colIdx, field, columnArray, scale);
          }
          break;
        }

        case SnowflakeType::Type::ANY:
        case SnowflakeType::Type::ARRAY:
        case SnowflakeType::Type::BOOLEAN:
        case SnowflakeType::Type::CHAR:
        case SnowflakeType::Type::OBJECT:
        case SnowflakeType::Type::BINARY:
        case SnowflakeType::Type::VARIANT:
        case SnowflakeType::Type::TEXT:
        case SnowflakeType::Type::REAL:
        case SnowflakeType::Type::DATE:
        {
          // Do not need to convert
          break;
        }

        case SnowflakeType::Type::TIME:
        {
          int scale = metaData
                          ? std::stoi(metaData->value(metaData->FindKey("scale")))
                          : 9;

          convertTimeColumn(batchIdx, colIdx, field, columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_NTZ:
        {
          int scale = metaData
                          ? std::stoi(metaData->value(metaData->FindKey("scale")))
                          : 9;

          convertTimestampColumn(batchIdx, colIdx, field, columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_LTZ:
        {
          int scale = metaData
                          ? std::stoi(metaData->value(metaData->FindKey("scale")))
                          : 9;

          convertTimestampColumn(batchIdx, colIdx, field, columnArray, scale, m_timezone);
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

          convertTimestampTZColumn(batchIdx, colIdx, field, columnArray, scale, byteLength);
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

CArrowTableIterator::CArrowTableIterator(PyObject* context, PyObject* batches)
: CArrowIterator(batches), m_context(context), m_pyTableObjRef(nullptr)
{
  PyObject* tz = PyObject_GetAttrString(m_context, "_timezone");
  PyArg_Parse(tz, "s", &m_timezone);
  Py_XDECREF(tz);
}

PyObject* CArrowTableIterator::next()
{
  bool firstDone = this->convertRecordBatchesToTable();
  if (firstDone && m_cTable)
  {
    m_pyTableObjRef.reset(arrow::py::wrap_table(m_cTable));
    return m_pyTableObjRef.get();
  }
  else
  {
    return Py_None;
  }
}

arrow::Status CArrowTableIterator::replaceColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field>& newField,
    const std::shared_ptr<arrow::Array>& newColumn)
{
  // replace the targeted column
  std::shared_ptr<arrow::RecordBatch> currentBatch = m_cRecordBatches[batchIdx];
  arrow::Status ret = currentBatch->AddColumn(colIdx+1, newField, newColumn, &currentBatch);
  if(!ret.ok())
  {
    return ret;
  }
  ret = currentBatch->RemoveColumn(colIdx, &currentBatch);
  if(!ret.ok())
  {
    return ret;
  }
  m_cRecordBatches[batchIdx] = currentBatch;
  return ret;
}

void CArrowTableIterator::convertScaledFixedNumberColumnToDoubleColumn(
  const unsigned int batchIdx,
  const int colIdx,
  const std::shared_ptr<arrow::Field> field,
  const std::shared_ptr<arrow::Array> columnArray,
  const int scale
)
{
  // Convert to arrow double/float64 column
  std::shared_ptr<arrow::Field> doubleField = std::make_shared<arrow::Field>(
      field->name(), arrow::float64(), field->nullable());
  arrow::DoubleBuilder builder(m_pool);
  arrow::Status ret;
  auto dt = field->type();
  for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
  {
    if (columnArray->IsValid(rowIdx))
    {
      auto originalVal = 0;
      switch (dt->id())
      {
        case arrow::Type::type::INT8:
          originalVal = std::static_pointer_cast<arrow::Int8Array>(columnArray)->Value(rowIdx);
          break;
        case arrow::Type::type::INT16:
          originalVal = std::static_pointer_cast<arrow::Int16Array>(columnArray)->Value(rowIdx);
          break;
        case arrow::Type::type::INT32:
          originalVal = std::static_pointer_cast<arrow::Int32Array>(columnArray)->Value(rowIdx);
          break;
        case arrow::Type::type::INT64:
          originalVal = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
          break;
        default:
          std::string errorInfo = Logger::formatString(
              "[Snowflake Exception] unknown arrow internal data type(%d) "
              "for FIXED data",
              dt->id());
          logger.error(errorInfo.c_str());
          return;
      }

      int s = scale;
      double val = 1.0 * originalVal;
      while (s > 9)
      {
        val = val / sf::internal::powTenSB4[9];
        s -= 9;
      }
      val = val / sf::internal::powTenSB4[s];
      ret = builder.Append(val);
    }
    else
    {
      ret = builder.AppendNull();
    }
    if(!ret.ok())
    {
      std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
          ", errorInfo: %s",
          dt->id(), ret.message().c_str());
      logger.error(errorInfo.c_str());
      PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      return;
    }
  }
  std::shared_ptr<arrow::Array> doubleArray;
  builder.Finish(&doubleArray);

  // replace the targeted column
  ret = replaceColumn(batchIdx, colIdx, doubleField, doubleArray);
  if(!ret.ok())
  {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow failed to replace column: internal data type(%d)"
        ", errorInfo: %s",
        dt->id(), ret.message().c_str());
    logger.error(errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
  }
}

void CArrowTableIterator::convertTimeColumn(
  const unsigned int batchIdx,
  const int colIdx,
  const std::shared_ptr<arrow::Field> field,
  const std::shared_ptr<arrow::Array> columnArray,
  const int scale
)
{
  std::shared_ptr<arrow::Field> tsField;
  std::shared_ptr<arrow::Array> tsArray;
  arrow::Status ret;
  auto dt = field->type();
  // Convert to arrow time column
  if (scale == 0)
  {
    auto timeType = arrow::time32(arrow::TimeUnit::SECOND);
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::Time32Builder builder(timeType, m_pool);


    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int32_t originalVal = std::static_pointer_cast<arrow::Int32Array>(columnArray)->Value(rowIdx);
        // unit is second
        ret = builder.Append(originalVal);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);

  }
  else if (scale <= 3)
  {
    auto timeType = arrow::time32(arrow::TimeUnit::MILLI);
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::Time32Builder builder(timeType, m_pool);

    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int32_t val = std::static_pointer_cast<arrow::Int32Array>(columnArray)->Value(rowIdx)
          * sf::internal::powTenSB4[3 - scale];
        // unit is millisecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }
  else if (scale <= 6)
  {
    auto timeType = arrow::time64(arrow::TimeUnit::MICRO);
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::Time64Builder builder(timeType, m_pool);

    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t val;
        switch (dt->id())
        {
          case arrow::Type::type::INT32:
            val = std::static_pointer_cast<arrow::Int32Array>(columnArray)->Value(rowIdx);
            break;
          case arrow::Type::type::INT64:
            val = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
            break;
          default:
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                dt->id());
            logger.error(errorInfo.c_str());
            return;
        }
        val *= sf::internal::powTenSB4[6 - scale];
        // unit is microsecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }
  else
  {
    // Note: Python/Pandas Time does not support nanoseconds,
    // So truncate the time values to microseconds
    auto timeType = arrow::time64(arrow::TimeUnit::MICRO);
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::Time64Builder builder(timeType, m_pool);

    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t val;
        switch (dt->id())
        {
          case arrow::Type::type::INT32:
            val = std::static_pointer_cast<arrow::Int32Array>(columnArray)->Value(rowIdx);
            break;
          case arrow::Type::type::INT64:
            val = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
            break;
          default:
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                dt->id());
            logger.error(errorInfo.c_str());
            return;
        }
        val /= sf::internal::powTenSB4[scale - 6];
        // unit is microsecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }

  // replace the targeted column
  ret = replaceColumn(batchIdx, colIdx, tsField, tsArray);
  if(!ret.ok())
  {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow failed to replace column: internal data type(%d)"
        ", errorInfo: %s",
        dt->id(), ret.message().c_str());
    logger.error(errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
  }
}

void CArrowTableIterator::convertTimestampColumn(
  const unsigned int batchIdx,
  const int colIdx,
  const std::shared_ptr<arrow::Field> field,
  const std::shared_ptr<arrow::Array> columnArray,
  const int scale,
  const std::string timezone
)
{
  std::shared_ptr<arrow::Field> tsField;
  std::shared_ptr<arrow::Array> tsArray;
  arrow::Status ret;
  std::shared_ptr<arrow::DataType> timeType;
  auto dt = field->type();
  // Convert to arrow time column
  if (scale == 0)
  {
    if (!timezone.empty())
    {
      timeType = arrow::timestamp(arrow::TimeUnit::SECOND, timezone);
    }
    else
    {
      timeType = arrow::timestamp(arrow::TimeUnit::SECOND);
    }
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::TimestampBuilder builder(timeType, m_pool);


    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t originalVal = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
        // unit is second
        ret = builder.Append(originalVal);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);

  }
  else if (scale <= 3)
  {
    if (!timezone.empty())
    {
      timeType = arrow::timestamp(arrow::TimeUnit::MILLI, timezone);
    }
    else
    {
      timeType = arrow::timestamp(arrow::TimeUnit::MILLI);
    }
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::TimestampBuilder builder(timeType, m_pool);

    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t val = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx)
          * sf::internal::powTenSB4[3 - scale];
        // unit is millisecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }
  else if (scale <= 6)
  {
    if (!timezone.empty())
    {
      timeType = arrow::timestamp(arrow::TimeUnit::MICRO, timezone);
    }
    else
    {
      timeType = arrow::timestamp(arrow::TimeUnit::MICRO);
    }
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::TimestampBuilder builder(timeType, m_pool);

    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t val;
        switch (dt->id())
        {
          case arrow::Type::type::INT64:
            val = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
            break;
          default:
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                dt->id());
            logger.error(errorInfo.c_str());
            return;
        }
        val *= sf::internal::powTenSB4[6 - scale];
        // unit is microsecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }
  else
  {
    if (!timezone.empty())
    {
      timeType = arrow::timestamp(arrow::TimeUnit::NANO, timezone);
    }
    else
    {
      timeType = arrow::timestamp(arrow::TimeUnit::NANO);
    }
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
    arrow::TimestampBuilder builder(timeType, m_pool);
    std::shared_ptr<arrow::StructArray> structArray;
    if (dt->id() == arrow::Type::type::STRUCT)
    {
      structArray = std::dynamic_pointer_cast<arrow::StructArray>(columnArray);
    }
    arrow::Status ret;
    for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
    {
      if (columnArray->IsValid(rowIdx))
      {
        int64_t val;
        switch (dt->id())
        {
          case arrow::Type::type::INT64:
            val = std::static_pointer_cast<arrow::Int64Array>(columnArray)->Value(rowIdx);
            val *= sf::internal::powTenSB4[9 - scale];
            break;
          case arrow::Type::type::STRUCT:
            {
              int64_t epoch = std::static_pointer_cast<arrow::Int64Array>(
                structArray->GetFieldByName(sf::internal::FIELD_NAME_EPOCH))->Value(rowIdx);
              int32_t fraction = std::static_pointer_cast<arrow::Int32Array>(
                structArray->GetFieldByName(sf::internal::FIELD_NAME_FRACTION))->Value(rowIdx);
              val = epoch * sf::internal::powTenSB4[9] + fraction;
            }
            break;
          default:
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                dt->id());
            logger.error(errorInfo.c_str());
            return;
        }
        // unit is nanosecond
        ret = builder.Append(val);
      }
      else
      {
        ret = builder.AppendNull();
      }
      if(!ret.ok())
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
            ", errorInfo: %s",
            dt->id(), ret.message().c_str());
        logger.error(errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }

    builder.Finish(&tsArray);
  }

  // replace the targeted column
  ret = replaceColumn(batchIdx, colIdx, tsField, tsArray);
  if(!ret.ok())
  {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow failed to replace column: internal data type(%d)"
        ", errorInfo: %s",
        dt->id(), ret.message().c_str());
    logger.error(errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
  }
}

void CArrowTableIterator::convertTimestampTZColumn(
  const unsigned int batchIdx,
  const int colIdx,
  const std::shared_ptr<arrow::Field> field,
  const std::shared_ptr<arrow::Array> columnArray,
  const int scale,
  const int byteLength)
{
  std::shared_ptr<arrow::Field> tsField;
  std::shared_ptr<arrow::Array> tsArray;
  std::shared_ptr<arrow::DataType> timeType;
  auto dt = field->type();
  // Convert to arrow time column
  std::shared_ptr<arrow::StructArray> structArray;
  structArray = std::dynamic_pointer_cast<arrow::StructArray>(columnArray);
  auto epochArray = std::static_pointer_cast<arrow::Int64Array>(
          structArray->GetFieldByName(sf::internal::FIELD_NAME_EPOCH));
  auto fractionArray = std::static_pointer_cast<arrow::Int32Array>(
          structArray->GetFieldByName(sf::internal::FIELD_NAME_FRACTION));
  auto timezoneIndexArray = std::static_pointer_cast<arrow::Int32Array>(
          structArray->GetFieldByName(sf::internal::FIELD_NAME_TIME_ZONE));

  if (scale == 0)
  {
    timeType = arrow::timestamp(arrow::TimeUnit::SECOND);
    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
  }
  else if (scale <= 3)
  {
    timeType = arrow::timestamp(arrow::TimeUnit::MILLI);

    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
  }
  else if (scale <= 6)
  {
    timeType = arrow::timestamp(arrow::TimeUnit::MICRO);

    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
  }
  else
  {
    timeType = arrow::timestamp(arrow::TimeUnit::NANO);

    tsField = std::make_shared<arrow::Field>(
      field->name(), timeType, field->nullable());
  }

  arrow::TimestampBuilder builder(timeType, m_pool);
  arrow::Status ret;
  for(int64_t rowIdx = 0; rowIdx < columnArray->length(); rowIdx++)
  {
    if (columnArray->IsValid(rowIdx))
    {
      if (byteLength == 8)
      {
        // two fields
        int64_t epoch = epochArray->Value(rowIdx);
        int32_t timezoneIndex = timezoneIndexArray->Value(rowIdx);
        // append value
        if (scale == 0)
        {
          ret = builder.Append(epoch);
        }
        else if (scale <= 3)
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[3-scale]);
        }
        else if (scale <= 6)
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[6-scale]);
        }
        else
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[9 - scale]);
        }
      }
      else if (byteLength == 16)
      {
        // three fields
        int64_t epoch = epochArray->Value(rowIdx);
        int32_t fraction = fractionArray->Value(rowIdx);
        int32_t timezoneIndex = timezoneIndexArray->Value(rowIdx);
        if (scale == 0)
        {
          ret = builder.Append(epoch);
        }
        else if (scale <= 3)
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[3-scale]
                  + fraction / sf::internal::powTenSB4[6]);
        }
        else if (scale <= 6)
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[6] + fraction / sf::internal::powTenSB4[3]);
        }
        else
        {
          ret = builder.Append(epoch * sf::internal::powTenSB4[9] + fraction);
        }
      }
      else
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
    else
    {
      ret = builder.AppendNull();
    }
    if(!ret.ok())
    {
      std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] arrow failed to append value: internal data type(%d)"
          ", errorInfo: %s",
          dt->id(), ret.message().c_str());
      logger.error(errorInfo.c_str());
      PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      return;
    }
  }

  builder.Finish(&tsArray);
  // replace the targeted column
  ret = replaceColumn(batchIdx, colIdx, tsField, tsArray);
  if(!ret.ok())
  {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow failed to replace column: internal data type(%d)"
        ", errorInfo: %s",
        dt->id(), ret.message().c_str());
    logger.error(errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
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
