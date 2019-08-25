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

namespace sf
{

/**
 * Arrow base iterator implementation in C++.
 */

class CArrowIterator
{
public:
  CArrowIterator() = default;

  virtual ~CArrowIterator() = default;

  /**
   * Add Arrow RecordBach to current chunk
   * @param rb recordbatch to be added
   */
  virtual void addRecordBatch(PyObject* rb);

  /**
   * @return a python object which might be current row or an Arrow Table
   */
  virtual PyObject* next() = 0;

  virtual void reset() = 0;

protected:
   /** list of all record batch in current chunk */
  std::vector<std::shared_ptr<arrow::RecordBatch>> m_cRecordBatches;

  static Logger logger;
};
}

#endif  // PC_ARROWITERATOR_HPP
