//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "CArrowTableIterator.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "Python/Common.hpp"
#include "SnowflakeType.hpp"
#include "Util/time.hpp"

namespace sf {

/**
 * This function is to make sure the arrow table can be successfully converted
 * to pandas dataframe using arrow's to_pandas method. Since some Snowflake
 * arrow columns are not supported, this method can map those to supported ones.
 * Specifically,
 *    All Snowflake fixed number with scale > 0 (expect decimal) will be
 * converted to Arrow float64/double column All Snowflake time columns will be
 * converted to Arrow Time column with unit = second, milli, or, micro. All
 * Snowflake timestamp columns will be converted to Arrow timestamp columns
 *    Specifically,
 *    timestampntz will be converted to Arrow timestamp with UTC
 *    timestampltz will be converted to Arrow timestamp with session time zone
 *    timestamptz will be converted to Arrow timestamp with UTC
 *    Since Arrow timestamp use int64_t internally so it may be out of range for
 * small and large timestamps
 */
void CArrowTableIterator::reconstructRecordBatches_nanoarrow() {
  int returnCode = 0;
  // Type conversion, the code needs to be optimized
  for (unsigned int batchIdx = 0; batchIdx < m_ipcArrowArrayViewVec.size();
       batchIdx++) {
    // each record batch will have its own list of newly created array and
    // schema
    m_newArrays.push_back(std::vector<nanoarrow::UniqueArray>());
    m_newSchemas.push_back(std::vector<nanoarrow::UniqueSchema>());

    nanoarrow::UniqueSchema copiedSchema;
    returnCode =
        ArrowSchemaDeepCopy(m_ipcArrowSchema.get(), copiedSchema.get());
    SF_CHECK_ARROW_RC(
        returnCode,
        "[Snowflake Exception] error copying arrow schema, error code: %d",
        returnCode);
    m_ipcSchemaArrayVec.push_back(std::move(copiedSchema));

    ArrowError error;
    int returnCode;
    for (int colIdx = 0; colIdx < m_ipcSchemaArrayVec[batchIdx]->n_children;
         colIdx++) {
      ArrowArrayView* columnArray =
          m_ipcArrowArrayViewVec[batchIdx]->children[colIdx];
      ArrowSchema* columnSchema =
          m_ipcSchemaArrayVec[batchIdx]->children[colIdx];
      ArrowSchemaView columnSchemaView;

      returnCode = ArrowSchemaViewInit(&columnSchemaView, columnSchema, &error);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error initializing "
                        "ArrowSchemaView : %s, error code: %d",
                        ArrowErrorMessage(&error), returnCode);

      ArrowStringView snowflakeLogicalType;
      const char* metadata =
          m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->metadata;
      returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("logicalType"),
                                         &snowflakeLogicalType);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error getting 'logicalType' "
                        "from Arrow metadata, error code: %d",
                        returnCode);
      SnowflakeType::Type st =
          SnowflakeType::snowflakeTypeFromString(std::string(
              snowflakeLogicalType.data, snowflakeLogicalType.size_bytes));

      // reconstruct columnArray in place
      switch (st) {
        case SnowflakeType::Type::FIXED: {
          int scale = 0;
          struct ArrowStringView scaleString = ArrowCharView(nullptr);
          if (metadata != nullptr) {
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"),
                                               &scaleString);
            SF_CHECK_ARROW_RC(returnCode,
                              "[Snowflake Exception] error getting 'scale' "
                              "from Arrow metadata, error code: %d",
                              returnCode);
            scale = std::stoi(
                std::string(scaleString.data, scaleString.size_bytes));
          }
          if (scale > 0 &&
              columnSchemaView.type != ArrowType::NANOARROW_TYPE_DECIMAL128) {
            logger->debug(__FILE__, __func__, __LINE__,
                          "Convert fixed number column to double column, "
                          "column scale %d, column type id: %d",
                          scale, columnSchemaView.type);
            convertScaledFixedNumberColumn_nanoarrow(
                batchIdx, colIdx, &columnSchemaView, columnArray, scale);
          }
          break;
        }

        case SnowflakeType::Type::ANY:
        case SnowflakeType::Type::ARRAY:
        case SnowflakeType::Type::BINARY:
        case SnowflakeType::Type::BOOLEAN:
        case SnowflakeType::Type::CHAR:
        case SnowflakeType::Type::DATE:
        case SnowflakeType::Type::MAP:
        case SnowflakeType::Type::OBJECT:
        case SnowflakeType::Type::REAL:
        case SnowflakeType::Type::TEXT:
        case SnowflakeType::Type::VARIANT:
        case SnowflakeType::Type::VECTOR: {
          // Do not need to convert
          break;
        }

        case SnowflakeType::Type::TIME: {
          int scale = 9;
          if (metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"),
                                               &scaleString);
            SF_CHECK_ARROW_RC(returnCode,
                              "[Snowflake Exception] error getting 'scale' "
                              "from Arrow metadata, error code: %d",
                              returnCode);
            scale = std::stoi(
                std::string(scaleString.data, scaleString.size_bytes));
          }

          convertTimeColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView,
                                      columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_NTZ: {
          int scale = 9;
          if (metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"),
                                               &scaleString);
            SF_CHECK_ARROW_RC(returnCode,
                              "[Snowflake Exception] error getting 'scale' "
                              "from Arrow metadata, error code: %d",
                              returnCode);
            scale = std::stoi(
                std::string(scaleString.data, scaleString.size_bytes));
          }
          convertTimestampColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView,
                                           columnArray, scale);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_LTZ: {
          int scale = 9;
          if (metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"),
                                               &scaleString);
            SF_CHECK_ARROW_RC(returnCode,
                              "[Snowflake Exception] error getting 'scale' "
                              "from Arrow metadata, error code: %d",
                              returnCode);
            scale = std::stoi(
                std::string(scaleString.data, scaleString.size_bytes));
          }

          convertTimestampColumn_nanoarrow(batchIdx, colIdx, &columnSchemaView,
                                           columnArray, scale, m_timezone);
          break;
        }

        case SnowflakeType::Type::TIMESTAMP_TZ: {
          struct ArrowStringView scaleString = ArrowCharView(nullptr);
          struct ArrowStringView byteLengthString = ArrowCharView(nullptr);
          int scale = 9;
          int byteLength = 16;
          if (metadata != nullptr) {
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"),
                                               &scaleString);
            SF_CHECK_ARROW_RC(returnCode,
                              "[Snowflake Exception] error getting 'scale' "
                              "from Arrow metadata, error code: %d",
                              returnCode);
            returnCode = ArrowMetadataGetValue(
                metadata, ArrowCharView("byteLength"), &byteLengthString);
            SF_CHECK_ARROW_RC(
                returnCode,
                "[Snowflake Exception] error getting 'byteLength' from Arrow "
                "metadata, error code: %d",
                returnCode);
            scale = std::stoi(
                std::string(scaleString.data, scaleString.size_bytes));
            byteLength = std::stoi(std::string(byteLengthString.data,
                                               byteLengthString.size_bytes));
          }

          convertTimestampTZColumn_nanoarrow(batchIdx, colIdx,
                                             &columnSchemaView, columnArray,
                                             scale, byteLength, m_timezone);
          break;
        }

        default: {
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

CArrowTableIterator::CArrowTableIterator(PyObject* context, char* arrow_bytes,
                                         int64_t arrow_bytes_size,
                                         const bool number_to_decimal)
    : CArrowIterator(arrow_bytes, arrow_bytes_size),
      m_context(context),
      m_convert_number_to_decimal(number_to_decimal) {
  if (py::checkPyError()) {
    return;
  }
  py::UniqueRef tz(PyObject_GetAttrString(m_context, "_timezone"));
  PyArg_Parse(tz.get(), "s", &m_timezone);
}

ReturnVal CArrowTableIterator::next() {
  bool firstDone = this->convertRecordBatchesToTable_nanoarrow();
  if (firstDone && !m_ipcArrowArrayVec.empty()) {
    return ReturnVal(Py_True, nullptr);
  } else {
    return ReturnVal(Py_None, nullptr);
  }
}

template <typename T>
double CArrowTableIterator::convertScaledFixedNumberToDouble(
    const unsigned int scale, T originalValue) {
  if (scale < 9) {
    // simply use divide to convert decimal value in double
    return (double)originalValue / sf::internal::powTenSB4[scale];
  } else {
    // when scale is large, convert the value to string first and then convert
    // it to double otherwise, it may loss precision
    std::string valStr = std::to_string(originalValue);
    int negative = valStr.at(0) == '-' ? 1 : 0;
    unsigned int digits = valStr.length() - negative;
    if (digits <= scale) {
      int numOfZeroes = scale - digits + 1;
      valStr.insert(negative, std::string(numOfZeroes, '0'));
    }
    valStr.insert(valStr.length() - scale, ".");
    std::size_t offset = 0;
    return std::stod(valStr, &offset);
  }
}

void CArrowTableIterator::convertScaledFixedNumberColumn_nanoarrow(
    const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
    ArrowArrayView* columnArray, const unsigned int scale) {
  // Convert scaled fixed number to either Double, or Decimal based on setting
  if (m_convert_number_to_decimal) {
    convertScaledFixedNumberColumnToDecimalColumn_nanoarrow(
        batchIdx, colIdx, field, columnArray, scale);
  } else {
    convertScaledFixedNumberColumnToDoubleColumn_nanoarrow(
        batchIdx, colIdx, field, columnArray, scale);
  }
}

void CArrowTableIterator::
    convertScaledFixedNumberColumnToDecimalColumn_nanoarrow(
        const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
        ArrowArrayView* columnArray, const unsigned int scale) {
  int returnCode = 0;
  // Convert to arrow double/float64 column
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();

  // create new schema
  ArrowSchemaInit(newSchema);
  newSchema->flags &=
      (field->schema->flags & ARROW_FLAG_NULLABLE);  // map to nullable()
  returnCode = ArrowSchemaSetTypeDecimal(newSchema, NANOARROW_TYPE_DECIMAL128,
                                         38, scale);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error setting arrow schema type "
                    "decimal, error code: %d",
                    returnCode);
  returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error setting schema name, error code: %d",
      returnCode);

  ArrowError error;
  returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error initializing ArrowArrayView "
                    "from schema : %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);

  returnCode = ArrowArrayStartAppending(newArray);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error appending arrow array, error code: %d",
      returnCode);

  for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
    if (ArrowArrayViewIsNull(columnArray, rowIdx)) {
      returnCode = ArrowArrayAppendNull(newArray, 1);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending null to arrow "
                        "array, error code: %d",
                        returnCode);
    } else {
      auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
      ArrowDecimal arrowDecimal;
      ArrowDecimalInit(&arrowDecimal, 128, 38, scale);
      ArrowDecimalSetInt(&arrowDecimal, originalVal);
      returnCode = ArrowArrayAppendDecimal(newArray, &arrowDecimal);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending decimal to "
                        "arrow array, error code: %d",
                        returnCode);
    }
  }
  returnCode = ArrowArrayFinishBuildingDefault(newArray, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error finishing building arrow "
                    "array: %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);
  m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  m_ipcArrowArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::
    convertScaledFixedNumberColumnToDoubleColumn_nanoarrow(
        const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
        ArrowArrayView* columnArray, const unsigned int scale) {
  int returnCode = 0;
  // Convert to arrow double/float64 column
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();

  // create new schema
  ArrowSchemaInit(newSchema);
  newSchema->flags &=
      (field->schema->flags & ARROW_FLAG_NULLABLE);  // map to nullable()
  returnCode = ArrowSchemaSetType(
      newSchema, NANOARROW_TYPE_DOUBLE);  // map to arrow:float64()
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error setting arrow schema type "
                    "double, error code: %d",
                    returnCode);
  returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error setting schema name, error code: %d",
      returnCode);

  ArrowError error;
  returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error initializing ArrowArrayView "
                    "from schema : %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);

  for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
    if (ArrowArrayViewIsNull(columnArray, rowIdx)) {
      returnCode = ArrowArrayAppendNull(newArray, 1);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending null to arrow "
                        "array, error code: %d",
                        returnCode);
    } else {
      auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
      double val = convertScaledFixedNumberToDouble(scale, originalVal);
      returnCode = ArrowArrayAppendDouble(newArray, val);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending double to arrow "
                        "array, error code: %d",
                        returnCode);
    }
  }
  returnCode = ArrowArrayFinishBuildingDefault(newArray, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error finishing building arrow "
                    "array: %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);
  m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  m_ipcArrowArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimeColumn_nanoarrow(
    const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
    ArrowArrayView* columnArray, const int scale) {
  int returnCode = 0;
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;

  // create new schema
  ArrowSchemaInit(newSchema);
  int64_t powTenSB4Val = 1;
  newSchema->flags &=
      (field->schema->flags & ARROW_FLAG_NULLABLE);  // map to nullable()
  if (scale == 0) {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME32,
                                            NANOARROW_TIME_UNIT_SECOND, NULL);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
  } else if (scale <= 3) {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME32,
                                            NANOARROW_TIME_UNIT_MILLI, NULL);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
    powTenSB4Val = sf::internal::powTenSB4[3 - scale];
  } else if (scale <= 6) {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME64,
                                            NANOARROW_TIME_UNIT_MICRO, NULL);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
    powTenSB4Val = sf::internal::powTenSB4[6 - scale];
  } else {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIME64,
                                            NANOARROW_TIME_UNIT_MICRO, NULL);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
    powTenSB4Val = sf::internal::powTenSB4[scale - 6];
  }
  returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error setting schema name, error code: %d",
      returnCode);

  returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error initializing ArrowArrayView "
                    "from schema : %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);

  returnCode = ArrowArrayStartAppending(newArray);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error appending arrow array, error code: %d",
      returnCode);

  for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
    if (ArrowArrayViewIsNull(columnArray, rowIdx)) {
      returnCode = ArrowArrayAppendNull(newArray, 1);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending null to arrow "
                        "array, error code: %d",
                        returnCode);
    } else {
      auto originalVal = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
      if (scale <= 6) {
        originalVal *= powTenSB4Val;
      } else {
        originalVal /= powTenSB4Val;
      }
      returnCode = ArrowArrayAppendInt(newArray, originalVal);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending int to arrow "
                        "array, error code: %d",
                        returnCode);
    }
  }

  returnCode = ArrowArrayFinishBuildingDefault(newArray, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error finishing building arrow "
                    "array: %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);
  m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  m_ipcArrowArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimestampColumn_nanoarrow(
    const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
    ArrowArrayView* columnArray, const int scale, const std::string timezone) {
  int returnCode = 0;
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;

  ArrowSchemaInit(newSchema);
  newSchema->flags &=
      (field->schema->flags & ARROW_FLAG_NULLABLE);  // map to nullable()

  // calculate has_overflow_to_downscale
  bool has_overflow_to_downscale = false;
  if (scale > 6 && field->type == NANOARROW_TYPE_STRUCT) {
    ArrowArrayView* epochArray;
    ArrowArrayView* fractionArray;
    for (int64_t i = 0; i < field->schema->n_children; i++) {
      ArrowSchema* c_schema = field->schema->children[i];
      if (std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) ==
          0) {
        epochArray = columnArray->children[i];
      } else if (std::strcmp(c_schema->name,
                             internal::FIELD_NAME_FRACTION.c_str()) == 0) {
        fractionArray = columnArray->children[i];
      } else {
        // do nothing
      }
    }

    int powTenSB4 = sf::internal::powTenSB4[9];
    for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
      if (!ArrowArrayViewIsNull(columnArray, rowIdx)) {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
        if (epoch > (INT64_MAX / powTenSB4) ||
            epoch < (INT64_MIN / powTenSB4)) {
          if (fraction % 1000 != 0) {
            std::string errorInfo = Logger::formatString(
                "The total number of nanoseconds %d%d overflows int64 range. "
                "If you use a timestamp with "
                "the nanosecond part over 6-digits in the Snowflake database, "
                "the timestamp must be "
                "between '1677-09-21 00:12:43.145224192' and '2262-04-11 "
                "23:47:16.854775807' to not overflow.",
                epoch, fraction);
            throw std::overflow_error(errorInfo.c_str());
          } else {
            has_overflow_to_downscale = true;
          }
        }
      }
    }
  }

  if (scale <= 6) {
    int64_t powTenSB4Val = 1;
    auto timeunit = NANOARROW_TIME_UNIT_SECOND;
    if (scale == 0) {
      timeunit = NANOARROW_TIME_UNIT_SECOND;
      powTenSB4Val = 1;
    } else if (scale <= 3) {
      timeunit = NANOARROW_TIME_UNIT_MILLI;
      powTenSB4Val = sf::internal::powTenSB4[3 - scale];
    } else if (scale <= 6) {
      timeunit = NANOARROW_TIME_UNIT_MICRO;
      powTenSB4Val = sf::internal::powTenSB4[6 - scale];
    }
    if (!timezone.empty()) {
      returnCode = ArrowSchemaSetTypeDateTime(
          newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error setting arrow schema type "
                        "DateTime, error code: %d",
                        returnCode);
    } else {
      returnCode = ArrowSchemaSetTypeDateTime(
          newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error setting arrow schema type "
                        "DateTime, error code: %d",
                        returnCode);
    }
    returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
    SF_CHECK_ARROW_RC(
        returnCode,
        "[Snowflake Exception] error setting schema name, error code: %d",
        returnCode);
    returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error initializing ArrowArrayView "
                      "from schema : %s, error code: %d",
                      ArrowErrorMessage(&error), returnCode);

    for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
      if (ArrowArrayViewIsNull(columnArray, rowIdx)) {
        returnCode = ArrowArrayAppendNull(newArray, 1);
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error appending null to arrow "
                          "array, error code: %d",
                          returnCode);
      } else {
        int64_t val = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
        val *= powTenSB4Val;
        returnCode = ArrowArrayAppendInt(newArray, val);
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error appending int to arrow "
                          "array, error code: %d",
                          returnCode);
      }
    }
  } else {
    int64_t val;
    if (field->type == NANOARROW_TYPE_STRUCT) {
      ArrowArrayView* epochArray;
      ArrowArrayView* fractionArray;
      for (int64_t i = 0; i < field->schema->n_children; i++) {
        ArrowSchema* c_schema = field->schema->children[i];
        if (std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) ==
            0) {
          epochArray = columnArray->children[i];
        } else if (std::strcmp(c_schema->name,
                               internal::FIELD_NAME_FRACTION.c_str()) == 0) {
          fractionArray = columnArray->children[i];
        } else {
          // do nothing
        }
      }

      auto timeunit = has_overflow_to_downscale ? NANOARROW_TIME_UNIT_MICRO
                                                : NANOARROW_TIME_UNIT_NANO;
      if (!timezone.empty()) {
        returnCode = ArrowSchemaSetTypeDateTime(
            newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error setting arrow schema "
                          "type DateTime, error code: %d",
                          returnCode);
      } else {
        returnCode = ArrowSchemaSetTypeDateTime(
            newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error setting arrow schema "
                          "type DateTime, error code: %d",
                          returnCode);
      }
      returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
      SF_CHECK_ARROW_RC(
          returnCode,
          "[Snowflake Exception] error setting schema name, error code: %d",
          returnCode);

      returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error initializing "
                        "ArrowArrayView from schema : %s, error code: %d",
                        ArrowErrorMessage(&error), returnCode);

      for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
        if (!ArrowArrayViewIsNull(columnArray, rowIdx)) {
          int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
          int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
          if (has_overflow_to_downscale) {
            val = epoch * sf::internal::powTenSB4[6] + fraction / 1000;
          } else {
            val = epoch * sf::internal::powTenSB4[9] + fraction;
          }
          returnCode = ArrowArrayAppendInt(newArray, val);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else {
          returnCode = ArrowArrayAppendNull(newArray, 1);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending null to "
                            "arrow array, error code: %d",
                            returnCode);
        }
      }
    } else if (field->type == NANOARROW_TYPE_INT64) {
      auto timeunit = has_overflow_to_downscale ? NANOARROW_TIME_UNIT_MICRO
                                                : NANOARROW_TIME_UNIT_NANO;
      if (!timezone.empty()) {
        returnCode = ArrowSchemaSetTypeDateTime(
            newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, timezone.c_str());
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error setting arrow schema "
                          "type DateTime, error code: %d",
                          returnCode);
      } else {
        returnCode = ArrowSchemaSetTypeDateTime(
            newSchema, NANOARROW_TYPE_TIMESTAMP, timeunit, NULL);
        SF_CHECK_ARROW_RC(returnCode,
                          "[Snowflake Exception] error setting arrow schema "
                          "type DateTime, error code: %d",
                          returnCode);
      }
      returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
      SF_CHECK_ARROW_RC(
          returnCode,
          "[Snowflake Exception] error setting schema name, error code: %d",
          returnCode);

      returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error initializing "
                        "ArrowArrayView from schema : %s, error code: %d",
                        ArrowErrorMessage(&error), returnCode);

      for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
        if (!ArrowArrayViewIsNull(columnArray, rowIdx)) {
          val = ArrowArrayViewGetIntUnsafe(columnArray, rowIdx);
          val *= sf::internal::powTenSB4[9 - scale];
          returnCode = ArrowArrayAppendInt(newArray, val);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else {
          returnCode = ArrowArrayAppendNull(newArray, 1);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending null to "
                            "arrow array, error code: %d",
                            returnCode);
        }
      }
    }
  }

  returnCode = ArrowArrayFinishBuildingDefault(newArray, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error finishing building arrow "
                    "array: %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);
  m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  m_ipcArrowArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

void CArrowTableIterator::convertTimestampTZColumn_nanoarrow(
    const unsigned int batchIdx, const int colIdx, ArrowSchemaView* field,
    ArrowArrayView* columnArray, const int scale, const int byteLength,
    const std::string timezone) {
  int returnCode = 0;
  nanoarrow::UniqueSchema newUniqueField;
  nanoarrow::UniqueArray newUniqueArray;
  ArrowSchema* newSchema = newUniqueField.get();
  ArrowArray* newArray = newUniqueArray.get();
  ArrowError error;
  ArrowSchemaInit(newSchema);
  newSchema->flags &=
      (field->schema->flags & ARROW_FLAG_NULLABLE);  // map to nullable()
  auto timeunit = NANOARROW_TIME_UNIT_SECOND;
  if (scale == 0) {
    timeunit = NANOARROW_TIME_UNIT_SECOND;
  } else if (scale <= 3) {
    timeunit = NANOARROW_TIME_UNIT_MILLI;
  } else if (scale <= 6) {
    timeunit = NANOARROW_TIME_UNIT_MICRO;
  } else {
    timeunit = NANOARROW_TIME_UNIT_NANO;
  }

  if (!timezone.empty()) {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP,
                                            timeunit, timezone.c_str());
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
  } else {
    returnCode = ArrowSchemaSetTypeDateTime(newSchema, NANOARROW_TYPE_TIMESTAMP,
                                            timeunit, NULL);
    SF_CHECK_ARROW_RC(returnCode,
                      "[Snowflake Exception] error setting arrow schema type "
                      "DateTime, error code: %d",
                      returnCode);
  }
  returnCode = ArrowSchemaSetName(newSchema, field->schema->name);
  SF_CHECK_ARROW_RC(
      returnCode,
      "[Snowflake Exception] error setting schema name, error code: %d",
      returnCode);

  returnCode = ArrowArrayInitFromSchema(newArray, newSchema, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error initializing ArrowArrayView "
                    "from schema : %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);

  ArrowArrayView* epochArray;
  ArrowArrayView* fractionArray;
  for (int64_t i = 0; i < field->schema->n_children; i++) {
    ArrowSchema* c_schema = field->schema->children[i];
    if (std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
      epochArray = columnArray->children[i];
    } else if (std::strcmp(c_schema->name,
                           internal::FIELD_NAME_FRACTION.c_str()) == 0) {
      fractionArray = columnArray->children[i];
    } else {
      // do nothing
    }
  }

  for (int64_t rowIdx = 0; rowIdx < columnArray->array->length; rowIdx++) {
    if (!ArrowArrayViewIsNull(columnArray, rowIdx)) {
      if (byteLength == 8) {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        if (scale == 0) {
          returnCode = ArrowArrayAppendInt(newArray, epoch);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else if (scale <= 3) {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[3 - scale]);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else if (scale <= 6) {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[6 - scale]);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[9 - scale]);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        }
      } else if (byteLength == 16) {
        int64_t epoch = ArrowArrayViewGetIntUnsafe(epochArray, rowIdx);
        int64_t fraction = ArrowArrayViewGetIntUnsafe(fractionArray, rowIdx);
        if (scale == 0) {
          returnCode = ArrowArrayAppendInt(newArray, epoch);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else if (scale <= 3) {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[3 - scale] +
                            fraction / sf::internal::powTenSB4[6]);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else if (scale <= 6) {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[6] +
                            fraction / sf::internal::powTenSB4[3]);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        } else {
          returnCode = ArrowArrayAppendInt(
              newArray, epoch * sf::internal::powTenSB4[9] + fraction);
          SF_CHECK_ARROW_RC(returnCode,
                            "[Snowflake Exception] error appending int to "
                            "arrow array, error code: %d",
                            returnCode);
        }
      } else {
        std::string errorInfo = Logger::formatString(
            "[Snowflake Exception] unknown arrow internal data type(%d) "
            "for TIMESTAMP_TZ data",
            NANOARROW_TYPE_ENUM_STRING[field->type]);
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    } else {
      returnCode = ArrowArrayAppendNull(newArray, 1);
      SF_CHECK_ARROW_RC(returnCode,
                        "[Snowflake Exception] error appending null to arrow "
                        "array, error code: %d",
                        returnCode);
    }
  }

  returnCode = ArrowArrayFinishBuildingDefault(newArray, &error);
  SF_CHECK_ARROW_RC(returnCode,
                    "[Snowflake Exception] error finishing building arrow "
                    "array: %s, error code: %d",
                    ArrowErrorMessage(&error), returnCode);
  m_ipcSchemaArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  ArrowSchemaMove(newSchema, m_ipcSchemaArrayVec[batchIdx]->children[colIdx]);
  m_ipcArrowArrayVec[batchIdx]->children[colIdx]->release(
      m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  ArrowArrayMove(newArray, m_ipcArrowArrayVec[batchIdx]->children[colIdx]);
  m_newArrays[batchIdx].push_back(std::move(newUniqueArray));
  m_newSchemas[batchIdx].push_back(std::move(newUniqueField));
}

bool CArrowTableIterator::convertRecordBatchesToTable_nanoarrow() {
  // only do conversion once and there exist some record batches
  if (!m_tableConverted && m_ipcArrowArrayViewVec.size() > 0) {
    reconstructRecordBatches_nanoarrow();
    return true;
  }
  return false;
}

std::vector<uintptr_t> CArrowTableIterator::getArrowArrayPtrs() {
  std::vector<uintptr_t> ret;
  for (size_t i = 0; i < m_ipcArrowArrayVec.size(); i++) {
    ret.push_back((uintptr_t)(void*)(m_ipcArrowArrayVec[i].get()));
  }
  return ret;
}

std::vector<uintptr_t> CArrowTableIterator::getArrowSchemaPtrs() {
  std::vector<uintptr_t> ret;
  for (size_t i = 0; i < m_ipcSchemaArrayVec.size(); i++) {
    ret.push_back((uintptr_t)(void*)(m_ipcSchemaArrayVec[i].get()));
  }
  return ret;
}

}  // namespace sf
