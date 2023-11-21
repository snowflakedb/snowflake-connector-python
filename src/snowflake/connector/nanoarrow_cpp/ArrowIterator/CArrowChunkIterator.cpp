//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "CArrowChunkIterator.hpp"
#include "SnowflakeType.hpp"
#include "IntConverter.hpp"
#include "StringConverter.hpp"
#include "FloatConverter.hpp"
#include "DecimalConverter.hpp"
#include "BinaryConverter.hpp"
#include "BooleanConverter.hpp"
#include "DateConverter.hpp"
#include "FixedSizeListConverter.hpp"
#include "TimeStampConverter.hpp"
#include "TimeConverter.hpp"
#include <memory>
#include <string>
#include <vector>

namespace sf
{

CArrowChunkIterator::CArrowChunkIterator(PyObject* context, char* arrow_bytes, int64_t arrow_bytes_size, PyObject *use_numpy)
: CArrowIterator(arrow_bytes, arrow_bytes_size), m_latestReturnedRow(nullptr), m_context(context)
{
  if (py::checkPyError()) {
    return;
  }
  m_currentBatchIndex = -1;
  m_rowIndexInBatch = -1;
  m_rowCountInBatch = 0;
  m_latestReturnedRow.reset();
  m_useNumpy = PyObject_IsTrue(use_numpy);

  m_batchCount = m_ipcArrowArrayVec.size();
  m_columnCount = m_batchCount > 0 ? m_ipcArrowSchema->n_children : 0;

  logger->debug(__FILE__, __func__, __LINE__, "Arrow chunk info: batchCount %d, columnCount %d, use_numpy: %d", m_batchCount,
               m_columnCount, m_useNumpy);
}

std::shared_ptr<ReturnVal> CArrowChunkIterator::next()
{
  m_rowIndexInBatch++;

  if (m_rowIndexInBatch < m_rowCountInBatch)
  {
    this->createRowPyObject();
    SF_CHECK_PYTHON_ERR()
    return std::make_shared<ReturnVal>(m_latestReturnedRow.get(), nullptr);
  }
  else
  {
    // the initialization took place in CArrowIterator constructor in which function
    // we can not raise error but we can set error , we check here to see if error occurred during initialization
    SF_CHECK_PYTHON_ERR();
    m_currentBatchIndex++;
    if (m_currentBatchIndex < m_batchCount)
    {
      m_rowIndexInBatch = 0;
      m_rowCountInBatch = m_ipcArrowArrayVec[m_currentBatchIndex]->length;
      this->initColumnConverters();
      SF_CHECK_PYTHON_ERR()

      logger->debug(__FILE__, __func__, __LINE__, "Current batch index: %d, rows in current batch: %d",
                  m_currentBatchIndex, m_rowCountInBatch);

      this->createRowPyObject();
      SF_CHECK_PYTHON_ERR()

      return std::make_shared<ReturnVal>(m_latestReturnedRow.get(), nullptr);
    }
  }

  /** It looks like no one will decrease the ref of this Py_None, so we don't
   * increment the ref count here */
  return std::make_shared<ReturnVal>(Py_None, nullptr);
}

void CArrowChunkIterator::createRowPyObject()
{
  m_latestReturnedRow.reset(PyTuple_New(m_columnCount));
  for (int i = 0; i < m_columnCount; i++)
  {
    // PyTuple_SET_ITEM steals a reference to the PyObject returned by toPyObject below
    PyTuple_SET_ITEM(
        m_latestReturnedRow.get(),
        i,
        m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
  }
  return;
}

void CArrowChunkIterator::initColumnConverters()
{
  m_currentBatchConverters.clear();
  ArrowError error;
  int returnCode = 0;
  for (int i = 0; i < m_ipcArrowSchema->n_children; i++)
  {

    ArrowSchema* columnSchema = m_ipcArrowSchema->children[i];
    ArrowSchemaView columnSchemaView;

    returnCode = ArrowSchemaViewInit(
        &columnSchemaView, columnSchema, &error);
    SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error initializing ArrowSchemaView: %s, error code: %d", ArrowErrorMessage(&error), returnCode);

    ArrowArrayView* array = m_ipcArrowArrayViewVec[m_currentBatchIndex]->children[i];

    struct ArrowStringView snowflakeLogicalType = ArrowCharView(nullptr);
    const char* metadata = m_ipcArrowSchema->children[i]->metadata;
    returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("logicalType"), &snowflakeLogicalType);
    SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'logicalType' from Arrow metadata, error code: %d", returnCode);

    SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
        std::string(snowflakeLogicalType.data, snowflakeLogicalType.size_bytes)
    );

    switch (st)
    {
      case SnowflakeType::Type::FIXED:
      {
        struct ArrowStringView scaleString = ArrowCharView(nullptr);
        struct ArrowStringView precisionString = ArrowCharView(nullptr);
        int scale = 0;
        int precision = 38;
        if(metadata != nullptr) {
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'scale' from Arrow metadata, error code: %d", returnCode);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("precision"), &precisionString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'precision' from Arrow metadata, error code: %d", returnCode);
            scale = std::stoi(std::string(scaleString.data, scaleString.size_bytes));
            precision = std::stoi(std::string(precisionString.data, precisionString.size_bytes));
        }

        switch(columnSchemaView.type)
        {
#define _SF_INIT_FIXED_CONVERTER(ARROW_TYPE) \
          case ArrowType::ARROW_TYPE: \
          {\
            if (scale > 0)\
            {\
              if (m_useNumpy)\
              {\
                m_currentBatchConverters.push_back(std::make_shared<\
                    sf::NumpyDecimalConverter>(\
                    array, precision, scale, m_context));\
              }\
              else\
              {\
                m_currentBatchConverters.push_back(std::make_shared<\
                    sf::DecimalFromIntConverter>(\
                    array, precision, scale));\
              }\
            }\
            else\
            {\
              if (m_useNumpy)\
              {\
                m_currentBatchConverters.push_back(\
                    std::make_shared<sf::NumpyIntConverter>(\
                    array, m_context));\
              }\
              else\
              {\
                m_currentBatchConverters.push_back(\
                    std::make_shared<sf::IntConverter>(\
                    array));\
              }\
            }\
            break;\
          }

          _SF_INIT_FIXED_CONVERTER(NANOARROW_TYPE_INT8)
          _SF_INIT_FIXED_CONVERTER(NANOARROW_TYPE_INT16)
          _SF_INIT_FIXED_CONVERTER(NANOARROW_TYPE_INT32)
          _SF_INIT_FIXED_CONVERTER(NANOARROW_TYPE_INT64)
#undef _SF_INIT_FIXED_CONVERTER

          case ArrowType::NANOARROW_TYPE_DECIMAL128:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::DecimalFromDecimalConverter>(m_context,
                                                                  array,
                                                                  scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                NANOARROW_TYPE_ENUM_STRING[columnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
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
            std::make_shared<sf::StringConverter>(array));
        break;
      }

      case SnowflakeType::Type::BOOLEAN:
      {
        m_currentBatchConverters.push_back(
            std::make_shared<sf::BooleanConverter>(array));
        break;
      }

      case SnowflakeType::Type::REAL:
      {
        if (m_useNumpy)
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::NumpyFloat64Converter>(array, m_context));
        }
        else
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::FloatConverter>(array));
        }
        break;
      }

      case SnowflakeType::Type::DATE:
      {
        if (m_useNumpy)
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::NumpyDateConverter>(array, m_context));
        }
        else
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::DateConverter>(array));
        }
        break;
      }

      case SnowflakeType::Type::BINARY:
      {
        m_currentBatchConverters.push_back(
            std::make_shared<sf::BinaryConverter>(array));
        break;
      }

      case SnowflakeType::Type::TIME:
      {
        int scale = 9;
        if(metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'scale' from Arrow metadata, error code: %d", returnCode);
            scale = std::stoi(std::string(scaleString.data, scaleString.size_bytes));
        }
        switch (columnSchemaView.type)
        {
          case NANOARROW_TYPE_INT32:
          case NANOARROW_TYPE_INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TimeConverter>(
                    array, scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIME data",
                NANOARROW_TYPE_ENUM_STRING[columnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_NTZ:
      {
        int scale = 9;
        if(metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'scale' from Arrow metadata, error code: %d", returnCode);
            scale = std::stoi(std::string(scaleString.data, scaleString.size_bytes));
        }
        switch (columnSchemaView.type)
        {
          case NANOARROW_TYPE_INT64:
          {
            if (m_useNumpy)
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::NumpyOneFieldTimeStampNTZConverter>(
                      array, scale, m_context));
            }
            else
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::OneFieldTimeStampNTZConverter>(
                      array, scale, m_context));
            }
            break;
          }

          case NANOARROW_TYPE_STRUCT:
          {
            if (m_useNumpy)
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::NumpyTwoFieldTimeStampNTZConverter>(
                      array, &columnSchemaView, scale, m_context));
            }
            else
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::TwoFieldTimeStampNTZConverter>(
                      array, &columnSchemaView, scale, m_context));
            }
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_NTZ data",
                NANOARROW_TYPE_ENUM_STRING[columnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_LTZ:
      {
        int scale = 9;
        if(metadata != nullptr) {
            struct ArrowStringView scaleString = ArrowCharView(nullptr);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'scale' from Arrow metadata, error code: %d", returnCode);
            scale = std::stoi(std::string(scaleString.data, scaleString.size_bytes));
        }
        switch (columnSchemaView.type)
        {
          case NANOARROW_TYPE_INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::OneFieldTimeStampLTZConverter>(
                    array, scale, m_context));
            break;
          }

          case NANOARROW_TYPE_STRUCT:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampLTZConverter>(
                    array, &columnSchemaView, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_LTZ data",
                NANOARROW_TYPE_ENUM_STRING[columnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
        break;
      }

      case SnowflakeType::Type::TIMESTAMP_TZ:
      {
        struct ArrowStringView scaleString = ArrowCharView(nullptr);
        struct ArrowStringView byteLengthString = ArrowCharView(nullptr);
        int scale = 9;
        int byteLength = 16;
        if(metadata != nullptr) {
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'scale' from Arrow metadata, error code: %d", returnCode);
            returnCode = ArrowMetadataGetValue(metadata, ArrowCharView("byteLength"), &byteLengthString);
            SF_CHECK_ARROW_RC(returnCode, "[Snowflake Exception] error getting 'byteLength' from Arrow metadata, error code: %d", returnCode);
            scale = std::stoi(std::string(scaleString.data, scaleString.size_bytes));
            byteLength = std::stoi(std::string(byteLengthString.data, byteLengthString.size_bytes));
        }
        switch (byteLength)
        {
          case 8:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampTZConverter>(
                    array, &columnSchemaView, scale, m_context));
            break;
          }

          case 16:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::ThreeFieldTimeStampTZConverter>(
                    array, &columnSchemaView, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_TZ data",
                NANOARROW_TYPE_ENUM_STRING[columnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }

        break;
      }

      case SnowflakeType::Type::VECTOR:
      {
        m_currentBatchConverters.push_back(std::make_shared<sf::FixedSizeListConverter>(array));
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
}

DictCArrowChunkIterator::DictCArrowChunkIterator(PyObject* context,
                                                 char* arrow_bytes, int64_t arrow_bytes_size,
                                                 PyObject* use_numpy)
: CArrowChunkIterator(context, arrow_bytes, arrow_bytes_size, use_numpy)
{
}

void DictCArrowChunkIterator::createRowPyObject()
{
  m_latestReturnedRow.reset(PyDict_New());
  for (int i = 0; i < m_ipcArrowSchema->n_children; i++)
  {
    py::UniqueRef value(m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
    if (!value.empty())
    {
      // PyDict_SetItemString doesn't steal a reference to value.get().
      PyDict_SetItemString(
          m_latestReturnedRow.get(),
          m_ipcArrowSchema->children[i]->name,
          value.get());
    }
  }
  return;
}

}  // namespace sf
