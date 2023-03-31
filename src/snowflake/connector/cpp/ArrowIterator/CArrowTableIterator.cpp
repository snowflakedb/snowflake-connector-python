//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
//

#include "CArrowTableIterator.hpp"
#include "SnowflakeType.hpp"
#include "Python/Common.hpp"
#include "Util/time.hpp"
#include <memory>
#include <string>
#include <vector>

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
void CArrowTableIterator::reconstructRecordBatches_nanoarrow()
{
  // Type conversion, the code needs to be optimized
  for (unsigned int batchIdx = 0; batchIdx <  m_cRecordBatches->size(); batchIdx++)
  {
    std::shared_ptr<arrow::RecordBatch> currentBatch = (*m_cRecordBatches)[batchIdx];
    std::shared_ptr<arrow::Schema> schema = currentBatch->schema();

    // each record batch will have its own list of newly created array and schema
    m_newArrays.push_back(std::vector<nanoarrow::UniqueArray>());
    m_newSchemas.push_back(std::vector<nanoarrow::UniqueSchema>());

    // These copies will be used if rebuilding the RecordBatch if necessary
    nanoarrow::UniqueSchema arrowSchema;
    nanoarrow::UniqueArray arrowArray;
    nanoarrow::UniqueArrayView arrowArrayView;

    // Recommended path
    // TODO: Export is not needed when using nanoarrow IPC to read schema
    arrow::Status exportBatchOk = arrow::ExportRecordBatch(
      *currentBatch, arrowArray.get(), arrowSchema.get());

    ArrowError error;
    int returnCode = ArrowArrayViewInitFromSchema(
      arrowArrayView.get(), arrowSchema.get(), &error);
    if (returnCode != NANOARROW_OK) {
      std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
        ArrowErrorMessage(&error)
      );
      logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
      PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    }

    returnCode = ArrowArrayViewSetArray(
        arrowArrayView.get(), arrowArray.get(), &error);
    if (returnCode != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] error initializing ArrowArrayView from array : %s",
          ArrowErrorMessage(&error)
        );
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    }

    m_nanoarrowTable.push_back(std::move(arrowArray));
    m_nanoarrowSchemas.push_back(std::move(arrowSchema));
    m_nanoarrowViews.push_back(std::move(arrowArrayView));

    for (int colIdx = 0; colIdx < currentBatch->num_columns(); colIdx++)
    {
      ArrowArrayView* columnArray = m_nanoarrowViews[batchIdx]->children[colIdx];
      ArrowSchema* columnSchema = m_nanoarrowSchemas[batchIdx]->children[colIdx];
      ArrowSchemaView columnSchemaView;

      returnCode = ArrowSchemaViewInit(
         &columnSchemaView, columnSchema, &error);
      if (returnCode != NANOARROW_OK) {
      std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] error initializing ArrowSchemaView : %s",
        ArrowErrorMessage(&error)
      );
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      }

      ArrowStringView snowflakeLogicalType;
      const char* metadata = m_nanoarrowSchemas[batchIdx]->children[colIdx]->metadata;
      ArrowMetadataGetValue(metadata, ArrowCharView("logicalType"), &snowflakeLogicalType);
      SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
        std::string(snowflakeLogicalType.data, snowflakeLogicalType.size_bytes)
      );

      // reconstruct columnArray in place
      switch (st)
      {
        case SnowflakeType::Type::FIXED:
        {
          int scale = 0;
          ArrowStringView scaleString;
          if(metadata != nullptr) {
              ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
              scale = std::stoi(scaleString.data);
          }
          if (scale > 0 && columnSchemaView.type != ArrowType::NANOARROW_TYPE_DECIMAL128)
          {
              // TODO: this log is causing seg fault
//            logger->debug(__FILE__, __func__, __LINE__, "Convert fixed number column to double column, column scale %d, column type id: %d",
//              scale, columnSchemaView.type);
            convertScaledFixedNumberColumn_nanoarrow(
                batchIdx,
                colIdx,
                &columnSchemaView,
                columnArray,
                scale
            );
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
            int scale = 9;
            if(metadata != nullptr) {
                ArrowStringView scaleString;
                ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
                scale = std::stoi(scaleString.data);
            }

          convertTimeColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView, columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_NTZ:
        {
          int scale = 9;
          if(metadata != nullptr) {
            ArrowStringView scaleString;
            ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            scale = std::stoi(scaleString.data);
          }
          convertTimestampColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView, columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_LTZ:
        {
            int scale = 9;
            if(metadata != nullptr) {
                ArrowStringView scaleString;
                ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
                scale = std::stoi(scaleString.data);
            }

          convertTimestampColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView, columnArray, scale,  m_timezone);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_TZ:
        {
            ArrowStringView scaleString;
            ArrowStringView byteLengthString;
            int scale = 9;
            int byteLength = 16;
            if(metadata != nullptr) {
                ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
                ArrowMetadataGetValue(metadata, ArrowCharView("byteLength"), &byteLengthString);
                scale = std::stoi(scaleString.data);
                byteLength = std::stoi(byteLengthString.data);
            }

          convertTimestampTZColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView, columnArray, scale, byteLength, m_timezone);
          break;
        }

        default:
        {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown snowflake data type : %s",
                snowflakeLogicalType.data);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
        }
      }
    }
    m_tableConverted = true;
  }
}

CArrowTableIterator::CArrowTableIterator(
PyObject* context,
std::vector<std::shared_ptr<arrow::RecordBatch>>* batches,
const bool number_to_decimal
)
: CArrowIterator(batches),
m_context(context),
m_convert_number_to_decimal(number_to_decimal)
{
  py::UniqueRef tz(PyObject_GetAttrString(m_context, "_timezone"));
  PyArg_Parse(tz.get(), "s", &m_timezone);
}

std::shared_ptr<ReturnVal> CArrowTableIterator::next()
{
  bool firstDone = this->convertRecordBatchesToTable_nanoarrow();
  if (firstDone && !m_nanoarrowTable.empty())
  {
    return std::make_shared<ReturnVal>(Py_True, nullptr);
  }
  else
  {
    return std::make_shared<ReturnVal>(Py_None, nullptr);
  }
}

template <typename T>
double CArrowTableIterator::convertScaledFixedNumberToDouble(
  const unsigned int scale,
  T originalValue
)
{
  if (scale < 9)
  {
    // simply use divide to convert decimal value in double
    return (double) originalValue / sf::internal::powTenSB4[scale];
  }
  else
  {
    // when scale is large, convert the value to string first and then convert it to double
    // otherwise, it may loss precision
    std::string valStr = std::to_string(originalValue);
    int negative = valStr.at(0) == '-' ? 1:0;
    unsigned int digits = valStr.length() - negative;
    if (digits <= scale)
    {
      int numOfZeroes = scale - digits + 1;
      valStr.insert(negative, std::string(numOfZeroes, '0'));
    }
    valStr.insert(valStr.length() - scale, ".");
    std::size_t offset = 0;
    return std::stod(valStr, &offset);
  }
}

void CArrowTableIterator::convertScaledFixedNumberColumn_nanoarrow(
  const unsigned int batchIdx,
  const int colIdx,
    ArrowSchemaView* field,
    ArrowArrayView* columnArray,
    const unsigned int scale
)
{
// Convert scaled fixed number to either Double, or Decimal based on setting
  if (m_convert_number_to_decimal){
    convertScaledFixedNumberColumnToDecimalColumn_nanoarrow(
      batchIdx,
      colIdx,
      field,
      columnArray,
      scale
      );
  } else {
    convertScaledFixedNumberColumnToDoubleColumn_nanoarrow(
      batchIdx,
      colIdx,
      field,
      columnArray,
      scale
      );
  }
}

void CArrowTableIterator::convertScaledFixedNumberColumnToDecimalColumn_nanoarrow(
  const unsigned int batchIdx,
  const int colIdx,
    ArrowSchemaView* field,
    ArrowArrayView* columnArray,
    const unsigned int scale
)
{
  // Convert to arrow double/float64 column
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();

  // create new schema
  ArrowSchemaInit(newSchema);
  newSchema->flags &= (field->schema->flags & ARROW_FLAG_NULLABLE); // map to nullable()
  ArrowSchemaSetType(newSchema, NANOARROW_TYPE_DECIMAL128);  // map to arrow:float64()
  ArrowSchemaSetName(newSchema, field->schema->name);

  ArrowError error;
  int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  if (returnCode != NANOARROW_OK) {
    std::string errorInfo = Logger::formatString(
      "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
      ArrowErrorMessage(&error)
    );
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
  }

  for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
  {
    if(ArrowArrayViewIsNull(columnArray, rowIdx)) {
        ArrowArrayAppendNull(newArray, 1);
    } else {
        auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
        // TODO: nanoarrow is missing appending a decimal value to array
    }
  }
  ArrowArrayFinishBuildingDefault(newArray, &error);
  m_nanoarrowSchemas[batchIdx]->children[colIdx]->release(m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  m_nanoarrowTable[batchIdx]->children[colIdx]->release(m_nanoarrowTable[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_nanoarrowTable[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertScaledFixedNumberColumnToDoubleColumn_nanoarrow(
    const unsigned int batchIdx,
    const int colIdx,
    ArrowSchemaView* field,
    ArrowArrayView* columnArray,
    const unsigned int scale
)
{
  // Convert to arrow double/float64 column
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();

  // create new schema
  ArrowSchemaInit(newSchema);
  newSchema->flags &= (field->schema->flags & ARROW_FLAG_NULLABLE); // map to nullable()
  ArrowSchemaSetType(newSchema, NANOARROW_TYPE_DOUBLE);  // map to arrow:float64()
  ArrowSchemaSetName(newSchema, field->schema->name);

  ArrowError error;
  int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  if (returnCode != NANOARROW_OK) {
    std::string errorInfo = Logger::formatString(
    "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
    ArrowErrorMessage(&error)
    );
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
  }

  for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
  {
    if(ArrowArrayViewIsNull(columnArray, rowIdx)) {
        ArrowArrayAppendNull(newArray, 1);
    } else {
        auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
        double val = convertScaledFixedNumberToDouble(scale, originalVal);
        ArrowArrayAppendDouble(newArray, val);
    }
  }
  ArrowArrayFinishBuildingDefault(newArray, &error);
  m_nanoarrowSchemas[batchIdx]->children[colIdx]->release(m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  m_nanoarrowTable[batchIdx]->children[colIdx]->release(m_nanoarrowTable[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_nanoarrowTable[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimeColumn_nanoarrow(
  const unsigned int batchIdx,
  const int colIdx,
  ArrowSchemaView* field,
  ArrowArrayView* columnArray,
  const int scale
)
{
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;

  // create new schema
  ArrowSchemaInit(newSchema);
  int64_t powTenSB4Val = 1;
  newSchema->flags &= (field->schema->flags & ARROW_FLAG_NULLABLE); // map to nullable()
  if (scale == 0)
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME32, NANOARROW_TIME_UNIT_SECOND,  NULL);
  }
  else if (scale <= 3)
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME32, NANOARROW_TIME_UNIT_MILLI,  NULL);
    powTenSB4Val = sf::internal::powTenSB4[3 - scale];
  }
  else if (scale <= 6)
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME64, NANOARROW_TIME_UNIT_MICRO,  NULL);
    powTenSB4Val = sf::internal::powTenSB4[6 - scale];
  }
  else
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME64, NANOARROW_TIME_UNIT_MICRO,  NULL);
    powTenSB4Val = sf::internal::powTenSB4[scale - 6];
  }
  ArrowSchemaSetName(newSchema, field->schema->name);
  int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  if (returnCode != NANOARROW_OK) {
    std::string errorInfo = Logger::formatString(
    "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
    ArrowErrorMessage(&error)
    );
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
  }

  for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
  {
    if(ArrowArrayViewIsNull(columnArray, rowIdx)) {
      ArrowArrayAppendNull(newArray, 1);
    } else {
      auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
      if(scale <= 6)
      {
        originalVal *= powTenSB4Val;
      }
      else
      {
        originalVal /= powTenSB4Val;
      }
      ArrowArrayAppendInt(newArray, originalVal);
    }
  }

  ArrowArrayFinishBuildingDefault(newArray, &error);
  m_nanoarrowSchemas[batchIdx]->children[colIdx]->release(m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  m_nanoarrowTable[batchIdx]->children[colIdx]->release(m_nanoarrowTable[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_nanoarrowTable[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimestampColumn_nanoarrow(
  const unsigned int batchIdx,
  const int colIdx,
  ArrowSchemaView* field,
  ArrowArrayView* columnArray,
  const int scale,
  const std::string timezone
)
{
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;

  ArrowSchemaInit(newSchema);
  newSchema->flags &= (field->schema->flags & ARROW_FLAG_NULLABLE); // map to nullable()

  // calculate has_overflow_to_downscale
  bool has_overflow_to_downscale = false;
  if (scale > 6 && field->type == NANOARROW_TYPE_STRUCT)
  {
    ArrowArrayView* epochArray;
    ArrowArrayView* fractionArray;
    for(int64_t i = 0; i < field->schema->n_children; i++) {
        ArrowSchema* c_schema = field->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            epochArray = columnArray->children[i];
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0) {
            fractionArray = columnArray->children[i];
        } else {
            //TODO raise error: unrecognized fields
        }
    }

    int powTenSB4 = sf::internal::powTenSB4[9];
    for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
    {
      if(!ArrowArrayViewIsNull(columnArray, rowIdx))
      {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
        if (epoch > (INT64_MAX / powTenSB4) || epoch < (INT64_MIN / powTenSB4))
        {
          if (fraction % 1000 != 0) {
            std::string errorInfo = Logger::formatString(
              "The total number of nanoseconds %d%d overflows int64 range. If you use a timestamp with "
              "the nanosecond part over 6-digits in the Snowflake database, the timestamp must be "
              "between '1677-09-21 00:12:43.145224192' and '2262-04-11 23:47:16.854775807' to not overflow."
              , epoch, fraction);
            throw std::overflow_error(errorInfo.c_str());
          } else {
            has_overflow_to_downscale = true;
          }
        }
      }
    }
  }


  if (scale <= 6)
  {
    int64_t powTenSB4Val = 1;
    auto timeunit = NANOARROW_TIME_UNIT_SECOND;
    if (scale == 0)
    {
      timeunit = NANOARROW_TIME_UNIT_SECOND;
      powTenSB4Val = 1;
    }
    else if (scale <= 3)
    {
      timeunit = NANOARROW_TIME_UNIT_MILLI;
      powTenSB4Val = sf::internal::powTenSB4[3 - scale];
    }
    else if(scale <= 6)
    {
      timeunit = NANOARROW_TIME_UNIT_MICRO;
      powTenSB4Val = sf::internal::powTenSB4[6 - scale];
    }
    if(!timezone.empty())
    {
        ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
    }
    else
    {
        ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
    }
    ArrowSchemaSetName(newSchema, field->schema->name);
    ArrowError error;
    int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
    if (returnCode != NANOARROW_OK) {
      std::string errorInfo = Logger::formatString(
      "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
      ArrowErrorMessage(&error)
      );
      logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
      PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    }
    for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
    {
        if(ArrowArrayViewIsNull(columnArray, rowIdx))
        {
          ArrowArrayAppendNull(newArray, 1);
        }
        else
        {
          int64_t val = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
          val *= powTenSB4Val;
          ArrowArrayAppendInt(newArray, val);
        }
    }
  }
  else
  {
    int64_t val;
    if (field->type == NANOARROW_TYPE_STRUCT)
     {
        ArrowArrayView* epochArray;
        ArrowArrayView* fractionArray;
        for(int64_t i = 0; i < field->schema->n_children; i++) {
            ArrowSchema* c_schema = field->schema->children[i];
            if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
                epochArray = columnArray->children[i];
            } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0) {
                fractionArray = columnArray->children[i];
            } else {
                //TODO raise error: unrecognized fields
            }
        }

        auto timeunit = has_overflow_to_downscale? NANOARROW_TIME_UNIT_MICRO: NANOARROW_TIME_UNIT_NANO;
        if(!timezone.empty())
        {
          ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
        }
        else
        {
          ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
        }
        ArrowSchemaSetName(newSchema, field->schema->name);
        ArrowError error;
        int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
        if (returnCode != NANOARROW_OK) {
          std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
          ArrowErrorMessage(&error)
          );
          logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
          PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        }
        for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
        {
          if(!ArrowArrayViewIsNull(columnArray, rowIdx))
          {
            int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
            int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
            if (has_overflow_to_downscale)
            {
              val = epoch * sf::internal::powTenSB4[6] + fraction / 1000;
            }
            else
            {
              val = epoch * sf::internal::powTenSB4[9] + fraction;
            }
            ArrowArrayAppendInt(newArray, val);
          }
          else
          {
            ArrowArrayAppendNull(newArray, 1);
          }
        }
    }
    else if (field->type == NANOARROW_TYPE_INT64)
    {
      auto timeunit = has_overflow_to_downscale? NANOARROW_TIME_UNIT_MICRO: NANOARROW_TIME_UNIT_NANO;
      if(!timezone.empty())
      {
        ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
      }
      else
      {
        ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
      }
      ArrowSchemaSetName(newSchema, field->schema->name);
      ArrowError error;
      int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
      if (returnCode != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
        ArrowErrorMessage(&error)
        );
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      }

      for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
      {
        if(!ArrowArrayViewIsNull(columnArray, rowIdx))
        {
          val = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
          val *= sf::internal::powTenSB4[9 - scale];
          ArrowArrayAppendInt(newArray, val);
        }
        else
        {
          ArrowArrayAppendNull(newArray, 1);
        }
      }
    }
  }

  ArrowArrayFinishBuildingDefault(newArray, &error);
  m_nanoarrowSchemas[batchIdx]->children[colIdx]->release(m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  m_nanoarrowTable[batchIdx]->children[colIdx]->release(m_nanoarrowTable[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_nanoarrowTable[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimestampTZColumn_nanoarrow(
  const unsigned int batchIdx,
  const int colIdx,
  ArrowSchemaView* field,
  ArrowArrayView* columnArray,
  const int scale,
  const int byteLength,
  const std::string timezone
)
{
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;
  ArrowSchemaInit(newSchema);
  newSchema->flags &= (field->schema->flags & ARROW_FLAG_NULLABLE); // map to nullable()
  auto timeunit = NANOARROW_TIME_UNIT_SECOND;
  if (scale == 0)
  {
    timeunit = NANOARROW_TIME_UNIT_SECOND;
  }
  else if (scale <= 3)
  {
    timeunit = NANOARROW_TIME_UNIT_MILLI;
  }
  else if (scale <= 6)
  {
    timeunit = NANOARROW_TIME_UNIT_MICRO;
  }
  else
  {
    timeunit = NANOARROW_TIME_UNIT_NANO;
  }

  if(!timezone.empty())
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
  }
  else
  {
    ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
  }
  ArrowSchemaSetName(newSchema, field->schema->name);

  int returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  if (returnCode != NANOARROW_OK) {
    std::string errorInfo = Logger::formatString(
    "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
    ArrowErrorMessage(&error)
    );
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
  }

  ArrowArrayView* epochArray;
  ArrowArrayView* fractionArray;
  for(int64_t i = 0; i < field->schema->n_children; i++) {
    ArrowSchema* c_schema = field->schema->children[i];
    if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
      epochArray = columnArray->children[i];
    } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0) {
      fractionArray = columnArray->children[i];
    } else {
      //TODO raise error: unrecognized fields
    }
  }

  for(int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++)
  {
    if(!ArrowArrayViewIsNull(columnArray, rowIdx))
    {
      if (byteLength == 8)
      {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        if (scale == 0)
        {
          ArrowArrayAppendInt(newArray, epoch);
        }
        else if (scale <= 3)
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[3 - scale]);
        }
        else if (scale <= 6)
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[6 - scale]);
        }
        else
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[9 - scale]);
        }
      }
      else if (byteLength == 16)
      {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
        if (scale == 0)
        {
          ArrowArrayAppendInt(newArray, epoch);
        }
        else if (scale <= 3)
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[3-scale]
                  + fraction / sf::internal::powTenSB4[6]);
        }
        else if (scale <= 6)
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[6] + fraction / sf::internal::powTenSB4[3]);
        }
        else
        {
          ArrowArrayAppendInt(newArray, epoch * sf::internal::powTenSB4[9] + fraction);
        }
      }
      else
      {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] unknown arrow internal data type(%d) "
            "for TIMESTAMP_TZ data",
            NANOARROW_TYPE_ENUM_STRING[field->type]);
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }
    else
    {
      ArrowArrayAppendNull(newArray, 1);
    }
  }

  ArrowArrayFinishBuildingDefault(newArray, &error);
  m_nanoarrowSchemas[batchIdx]->children[colIdx]->release(m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_nanoarrowSchemas[batchIdx]->children[colIdx]);
  m_nanoarrowTable[batchIdx]->children[colIdx]->release(m_nanoarrowTable[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_nanoarrowTable[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

bool CArrowTableIterator::convertRecordBatchesToTable_nanoarrow()
{
  // only do conversion once and there exist some record batches
  if (!m_tableConverted && !m_cRecordBatches->empty())
  {
    reconstructRecordBatches_nanoarrow();
    return true;
  }
  return false;
}

std::vector<uintptr_t> CArrowTableIterator::getArrowArrayPtrs() {
    std::vector<uintptr_t> ret;
    for(size_t i = 0; i < m_nanoarrowTable.size(); i++) {
        ret.push_back((uintptr_t)(void*)(m_nanoarrowTable[i].get()));
    }
    return ret;
}

std::vector<uintptr_t> CArrowTableIterator::getArrowSchemaPtrs() {
    std::vector<uintptr_t> ret;
    for(size_t i = 0; i < m_nanoarrowSchemas.size(); i++) {
        ret.push_back((uintptr_t)(void*)(m_nanoarrowSchemas[i].get()));
    }
    return ret;
}

} // namespace sf
