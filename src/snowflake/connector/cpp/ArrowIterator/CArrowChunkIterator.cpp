//
// Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
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
#include "TimeStampConverter.hpp"
#include "TimeConverter.hpp"
#include "nanoarrow.h"
#include "arrow/c/bridge.h"
#include <memory>
#include <string>
#include <vector>
#include <iostream>

static const char* NANOARROW_TYPE_ENUM_STRING[] = {
    "NANOARROW_TYPE_UNINITIALIZED",
    "NANOARROW_TYPE_NA",
    "NANOARROW_TYPE_BOOL",
    "NANOARROW_TYPE_UINT8",
    "NANOARROW_TYPE_INT8",
    "NANOARROW_TYPE_UINT16",
    "NANOARROW_TYPE_INT16",
    "NANOARROW_TYPE_UINT32",
    "NANOARROW_TYPE_INT32",
    "NANOARROW_TYPE_UINT64",
    "NANOARROW_TYPE_INT64",
    "NANOARROW_TYPE_HALF_FLOAT",
    "NANOARROW_TYPE_FLOAT",
    "NANOARROW_TYPE_DOUBLE",
    "NANOARROW_TYPE_STRING",
    "NANOARROW_TYPE_BINARY",
    "NANOARROW_TYPE_FIXED_SIZE_BINARY",
    "NANOARROW_TYPE_DATE32",
    "NANOARROW_TYPE_DATE64",
    "NANOARROW_TYPE_TIMESTAMP",
    "NANOARROW_TYPE_TIME32",
    "NANOARROW_TYPE_TIME64",
    "NANOARROW_TYPE_INTERVAL_MONTHS",
    "NANOARROW_TYPE_INTERVAL_DAY_TIME",
    "NANOARROW_TYPE_DECIMAL128",
    "NANOARROW_TYPE_DECIMAL256",
    "NANOARROW_TYPE_LIST",
    "NANOARROW_TYPE_STRUCT",
    "NANOARROW_TYPE_SPARSE_UNION",
    "NANOARROW_TYPE_DENSE_UNION",
    "NANOARROW_TYPE_DICTIONARY",
    "NANOARROW_TYPE_MAP",
    "NANOARROW_TYPE_EXTENSION",
    "NANOARROW_TYPE_FIXED_SIZE_LIST",
    "NANOARROW_TYPE_DURATION",
    "NANOARROW_TYPE_LARGE_STRING",
    "NANOARROW_TYPE_LARGE_BINARY",
    "NANOARROW_TYPE_LARGE_LIST",
    "NANOARROW_TYPE_INTERVAL_MONTH_DAY_NANO"
};

#define SF_CHECK_PYTHON_ERR() \
  if (py::checkPyError())\
  {\
    PyObject *type, * val, *traceback;\
    PyErr_Fetch(&type, &val, &traceback);\
    PyErr_Clear();\
    m_currentPyException.reset(val);\
\
    Py_XDECREF(type);\
    Py_XDECREF(traceback);\
\
    return std::make_shared<ReturnVal>(nullptr, m_currentPyException.get());\
  }


namespace sf
{

CArrowChunkIterator::CArrowChunkIterator(PyObject* context, std::vector<std::shared_ptr<arrow::RecordBatch>> *batches,
                                         PyObject* use_numpy)
: CArrowIterator(batches), m_latestReturnedRow(nullptr), m_context(context)
{
  m_batchCount = m_cRecordBatches->size();
  m_columnCount = m_batchCount > 0 ? (*m_cRecordBatches)[0]->num_columns() : 0;
  m_currentBatchIndex = -1;
  m_rowIndexInBatch = -1;
  m_rowCountInBatch = 0;
  m_latestReturnedRow.reset();
  m_useNumpy = PyObject_IsTrue(use_numpy);

  logger->debug(__FILE__, __func__, __LINE__, "Arrow chunk info: batchCount %d, columnCount %d, use_numpy: %d", m_batchCount,
               m_columnCount, m_useNumpy);
}

CArrowChunkIterator::~CArrowChunkIterator()
{
    for(int i = 0; i < m_arrays.size(); i += 1) {
        m_arrays[i]->release(m_arrays[i].get());
        ArrowArrayViewReset(m_arrayViews[i].get());
    }
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
    m_currentBatchIndex++;
    if (m_currentBatchIndex < m_batchCount)
    {
      m_rowIndexInBatch = 0;
      m_rowCountInBatch = (*m_cRecordBatches)[m_currentBatchIndex]->num_rows();
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
  m_currentSchema = currentBatch->schema();

  nanoarrow::UniqueSchema nanoarrowSchema;
  // TODO: Export is not needed when using nanoarrow IPC to read schema
  arrow::ExportSchema(*m_currentSchema, nanoarrowSchema.get());

  for (int i = 0; i < currentBatch->num_columns(); i++)
  {
    std::shared_ptr<arrow::Array> columnArray = currentBatch->column(i);

    nanoarrow::UniqueSchema nanoarrowColumnSchemaUnique(nanoarrowSchema->children[i]);
    ArrowSchemaView nanoarrowColumnSchemaView;
    ArrowError error;
    ArrowSchemaViewInit(&nanoarrowColumnSchemaView, nanoarrowColumnSchemaUnique.get(), &error);

    std::shared_ptr<ArrowArray> nanoarrowUniqueColumnArrowArray = std::make_shared<ArrowArray>();
    std::shared_ptr<ArrowArrayView> nanoarrowUniqueColumnArrowArrayView = std::make_shared<ArrowArrayView>();

    arrow::ExportArray(*columnArray, nanoarrowUniqueColumnArrowArray.get());

    int res = 0;
    res = ArrowArrayViewInitFromSchema(nanoarrowUniqueColumnArrowArrayView.get(), nanoarrowColumnSchemaUnique.get(), &error);
    if(res != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString("ArrowArrayViewInitFromSchema failure");
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    }

    res = ArrowArrayViewSetArray(nanoarrowUniqueColumnArrowArrayView.get(), nanoarrowUniqueColumnArrowArray.get(), &error);
    if(res != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString("ArrowArrayViewSetArray failure");
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    }

    std::shared_ptr<ArrowArrayView> nanoarrowColumnArrowArrayViewInstance = nanoarrowUniqueColumnArrowArrayView;
    m_arrays.push_back(nanoarrowUniqueColumnArrowArray);
    m_arrayViews.push_back(nanoarrowUniqueColumnArrowArrayView);

    ArrowStringView snowflakeLogicalType;
    const char* metadata = nanoarrowSchema->children[i]->metadata;
    ArrowMetadataGetValue(metadata, ArrowCharView("logicalType"), &snowflakeLogicalType);
    SnowflakeType::Type st = SnowflakeType::snowflakeTypeFromString(
        std::string(snowflakeLogicalType.data, snowflakeLogicalType.size_bytes)
    );

    switch (st)
    {
      case SnowflakeType::Type::FIXED:
      {
        ArrowStringView scaleString;
        ArrowStringView precisionString;
        int scale = 0;
        int precision = 38;
        if(metadata != nullptr) {
            ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            ArrowMetadataGetValue(metadata, ArrowCharView("precision"), &precisionString);
            scale = std::stoi(scaleString.data);
            precision = std::stoi(precisionString.data);
        }

        switch(nanoarrowColumnSchemaView.type)
        {
#define _SF_INIT_FIXED_CONVERTER(ARROW_TYPE) \
          case ArrowType::ARROW_TYPE: \
          {\
            if (scale > 0)\
            {\
              if (m_useNumpy)\
              {\
                m_currentBatchConverters.push_back(std::make_shared<\
                    sf::NumpyDecimalConverter<ArrowArrayView>>(\
                    nanoarrowColumnArrowArrayViewInstance, precision, scale, m_context));\
              }\
              else\
              {\
                m_currentBatchConverters.push_back(std::make_shared<\
                    sf::DecimalFromIntConverter<ArrowArrayView>>(\
                    nanoarrowColumnArrowArrayViewInstance, precision, scale));\
              }\
            }\
            else\
            {\
              if (m_useNumpy)\
              {\
                m_currentBatchConverters.push_back(\
                    std::make_shared<sf::NumpyIntConverter<ArrowArrayView>>(\
                    nanoarrowColumnArrowArrayViewInstance, m_context));\
              }\
              else\
              {\
                m_currentBatchConverters.push_back(\
                    std::make_shared<sf::IntConverter<ArrowArrayView>>(\
                    nanoarrowColumnArrowArrayViewInstance));\
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
                                                                  nanoarrowColumnArrowArrayViewInstance,
                                                                  scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for FIXED data",
                NANOARROW_TYPE_ENUM_STRING[nanoarrowColumnSchemaView.type]);
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
            std::make_shared<sf::StringConverter>(nanoarrowColumnArrowArrayViewInstance));
        break;
      }

      case SnowflakeType::Type::BOOLEAN:
      {
        m_currentBatchConverters.push_back(
            std::make_shared<sf::BooleanConverter>(nanoarrowColumnArrowArrayViewInstance));
        break;
      }

      case SnowflakeType::Type::REAL:
      {
        if (m_useNumpy)
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::NumpyFloat64Converter>(nanoarrowColumnArrowArrayViewInstance, m_context));
        }
        else
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::FloatConverter>(nanoarrowColumnArrowArrayViewInstance));
        }
        break;
      }

      case SnowflakeType::Type::DATE:
      {
        if (m_useNumpy)
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::NumpyDateConverter>(nanoarrowColumnArrowArrayViewInstance, m_context));
        }
        else
        {
          m_currentBatchConverters.push_back(
              std::make_shared<sf::DateConverter>(nanoarrowColumnArrowArrayViewInstance));
        }
        break;
      }

      case SnowflakeType::Type::BINARY:
      {
        m_currentBatchConverters.push_back(
            std::make_shared<sf::BinaryConverter>(nanoarrowColumnArrowArrayViewInstance));
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
        switch (nanoarrowColumnSchemaView.type)
        {
          case NANOARROW_TYPE_INT32:
          case NANOARROW_TYPE_INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TimeConverter<ArrowArrayView>>(
                    nanoarrowColumnArrowArrayViewInstance, scale));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIME data",
                NANOARROW_TYPE_ENUM_STRING[nanoarrowColumnSchemaView.type]);
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
            ArrowStringView scaleString;
            ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            scale = std::stoi(scaleString.data);
        }
        switch (nanoarrowColumnSchemaView.type)
        {
          case NANOARROW_TYPE_INT64:
          {
            if (m_useNumpy)
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::NumpyOneFieldTimeStampNTZConverter>(
                      nanoarrowColumnArrowArrayViewInstance, scale, m_context));
            }
            else
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::OneFieldTimeStampNTZConverter>(
                      nanoarrowColumnArrowArrayViewInstance, scale, m_context));
            }
            break;
          }

          case NANOARROW_TYPE_STRUCT:
          {
            if (m_useNumpy)
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::NumpyTwoFieldTimeStampNTZConverter>(
                      nanoarrowColumnArrowArrayViewInstance, &nanoarrowColumnSchemaView, scale, m_context));
            }
            else
            {
              m_currentBatchConverters.push_back(
                  std::make_shared<sf::TwoFieldTimeStampNTZConverter>(
                      nanoarrowColumnArrowArrayViewInstance, &nanoarrowColumnSchemaView, scale, m_context));
            }
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_NTZ data",
                NANOARROW_TYPE_ENUM_STRING[nanoarrowColumnSchemaView.type]);
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
            ArrowStringView scaleString;
            ArrowMetadataGetValue(metadata, ArrowCharView("scale"), &scaleString);
            scale = std::stoi(scaleString.data);
        }
        switch (nanoarrowColumnSchemaView.type)
        {
          case NANOARROW_TYPE_INT64:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::OneFieldTimeStampLTZConverter>(
                    nanoarrowColumnArrowArrayViewInstance, scale, m_context));
            break;
          }

          case NANOARROW_TYPE_STRUCT:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampLTZConverter>(
                    nanoarrowColumnArrowArrayViewInstance, &nanoarrowColumnSchemaView, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_LTZ data",
                NANOARROW_TYPE_ENUM_STRING[nanoarrowColumnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
            PyErr_SetString(PyExc_Exception, errorInfo.c_str());
            return;
          }
        }
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
        switch (byteLength)
        {
          case 8:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::TwoFieldTimeStampTZConverter>(
                    nanoarrowColumnArrowArrayViewInstance, &nanoarrowColumnSchemaView, scale, m_context));
            break;
          }

          case 16:
          {
            m_currentBatchConverters.push_back(
                std::make_shared<sf::ThreeFieldTimeStampTZConverter>(
                    nanoarrowColumnArrowArrayViewInstance, &nanoarrowColumnSchemaView, scale, m_context));
            break;
          }

          default:
          {
            std::string errorInfo = Logger::formatString(
                "[Snowflake Exception] unknown arrow internal data type(%d) "
                "for TIMESTAMP_TZ data",
                NANOARROW_TYPE_ENUM_STRING[nanoarrowColumnSchemaView.type]);
            logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
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
            snowflakeLogicalType.data);
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
        return;
      }
    }
  }
}

DictCArrowChunkIterator::DictCArrowChunkIterator(PyObject* context,
                                                 std::vector<std::shared_ptr<arrow::RecordBatch>> * batches,
                                                 PyObject* use_numpy)
: CArrowChunkIterator(context, batches, use_numpy)
{
}

void DictCArrowChunkIterator::createRowPyObject()
{
  m_latestReturnedRow.reset(PyDict_New());
  for (int i = 0; i < m_currentSchema->num_fields(); i++)
  {
    py::UniqueRef value(m_currentBatchConverters[i]->toPyObject(m_rowIndexInBatch));
    if (!value.empty())
    {
      // PyDict_SetItemString doesn't steal a reference to value.get().
      PyDict_SetItemString(
          m_latestReturnedRow.get(),
          m_currentSchema->field(i)->name().c_str(),
          value.get());
    }
  }
  return;
}

}  // namespace sf
