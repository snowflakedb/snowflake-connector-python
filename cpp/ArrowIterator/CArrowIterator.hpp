/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_ARROWITERATOR_HPP
#define PC_ARROWITERATOR_HPP

#include <Python.h>
#include <vector>
#include <arrow/python/platform.h>
#include <arrow/api.h>
#include <arrow/python/pyarrow.h>
#include "logging.hpp"

#define SF_CHECK_ARROW_RC(arrow_status, format_string, ...) \
  if (!arrow_status.ok()) \
  { \
    std::string errorInfo = Logger::formatString(format_string, ##__VA_ARGS__); \
    logger.error(errorInfo.c_str()); \
    PyErr_SetString(PyExc_Exception, errorInfo.c_str()); \
    return; \
  }

#define SF_CHECK_ARROW_RC_AND_RETURN(arrow_status, ret_val, format_string, ...) \
  if (!arrow_status.ok()) \
  { \
    std::string errorInfo = Logger::formatString(format_string, ##__VA_ARGS__); \
    logger.error(errorInfo.c_str()); \
    PyErr_SetString(PyExc_Exception, errorInfo.c_str()); \
    return ret_val; \
  }

namespace sf
{

/**
 * Arrow base iterator implementation in C++.
 */

class CArrowIterator
{
public:
  CArrowIterator(std::vector<std::shared_ptr<arrow::RecordBatch>> * batches);

  virtual ~CArrowIterator() = default;

  /**
   * @return a python object which might be current row or an Arrow Table
   */
  virtual PyObject* next() = 0;

protected:
   /** list of all record batch in current chunk */
  std::vector<std::shared_ptr<arrow::RecordBatch>> *m_cRecordBatches;

  static Logger logger;
};
}

#endif  // PC_ARROWITERATOR_HPP
