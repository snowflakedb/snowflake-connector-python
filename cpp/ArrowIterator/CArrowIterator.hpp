/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_ARROWITERATOR_HPP
#define PC_ARROWITERATOR_HPP

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include <Python.h>
#include <vector>
#include <arrow/python/platform.h>
#include <arrow/api.h>
#include <arrow/python/pyarrow.h>
#pragma GCC diagnostic pop
#include "logging.hpp"

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
