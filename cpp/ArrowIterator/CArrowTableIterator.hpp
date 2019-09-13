/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_ARROWTABLEITERATOR_HPP
#define PC_ARROWTABLEITERATOR_HPP

#include <arrow/table.h>
#include "CArrowIterator.hpp"

namespace sf
{

/**
 * Arrow table iterator implementation in C++.
 * The caller will ask for an Arrow Table to be returned back to Python
 * This conversion is zero-copy, just aggregate every columns from mutiple record batches
 * and build a new table.
 */
class CArrowTableIterator : public CArrowIterator
{
public:
  /**
   * Constructor
   */
  CArrowTableIterator(PyObject* context, PyObject* batches);

  /**
   * Desctructor
   */
  ~CArrowTableIterator() = default;

  /**
   * @return an arrow table containing all data in all record batches
   */
  PyObject* next() override;

private:
  /* arrow table of all record batches in current chunk */
  std::shared_ptr<arrow::Table> m_cTable;

  /** arrow format convert context for the current session */
  PyObject* m_context;

  /**
   * Reconstruct record batches with type conversion in place
   */
  void reconstructRecordBatches();

  /**
   * Convert all current RecordBatches to Arrow Table
   * @return if conversion is executed at first time and sucessfully
   */
  bool convertRecordBatchesToTable();
};
}

#endif  // PC_ARROWTABLEITERATOR_HPP
