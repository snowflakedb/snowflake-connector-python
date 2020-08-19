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
 * This conversion is zero-copy, just aggregate every columns from multiple record batches
 * and build a new table.
 */
class CArrowTableIterator : public CArrowIterator
{
public:
  /**
   * Constructor
   */
  CArrowTableIterator(PyObject* context, std::vector<std::shared_ptr<arrow::RecordBatch>>* batches);

  /**
   * Destructor
   */
  ~CArrowTableIterator() = default;

  /**
   * @return an arrow table containing all data in all record batches
   */
  std::shared_ptr<ReturnVal> next() override;

private:
  /* arrow table of all record batches in current chunk */
  std::shared_ptr<arrow::Table> m_cTable;

  /** arrow format convert context for the current session */
  PyObject* m_context;

  /** reference to PyObject */
  py::UniqueRef m_pyTableObjRef;

  /**
   * arrow memory buffer to allocate type converted arrays for fetching pandas from arrow
   */
  arrow::MemoryPool* m_pool = arrow::default_memory_pool();

  /** local time zone */
  char* m_timezone;

  /**
   * Reconstruct record batches with type conversion in place
   */
  void reconstructRecordBatches();

  /**
   * Convert all current RecordBatches to Arrow Table
   * @return if conversion is executed at first time and successfully
   */
  bool convertRecordBatchesToTable();

  /**
   * replace column with the new column in place
   */
  arrow::Status replaceColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field>& newField,
    const std::shared_ptr<arrow::Array>& newColumn);

  /**
   * convert scaled fixed number column to double column
   */
  void convertScaledFixedNumberColumnToDoubleColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field> field,
    const std::shared_ptr<arrow::Array> columnArray,
    const unsigned int scale);

  /**
   * convert Snowflake Time column (Arrow int32/int64) to Arrow Time column
   * Since Python/Pandas Time does not support nanoseconds, this function truncates values to microseconds if necessary
   */
  void convertTimeColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field> field,
    const std::shared_ptr<arrow::Array> columnArray,
    const int scale);

  /**
   * convert Snowflake TimestampNTZ/TimestampLTZ column to Arrow Timestamp column
   */
  void convertTimestampColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field> field,
    const std::shared_ptr<arrow::Array> columnArray,
    const int scale,
    const std::string timezone="");

  /**
   * convert Snowflake TimestampTZ column to Arrow Timestamp column in UTC
   * Arrow Timestamp does not support time zone info in each value, so this method convert TimestampTZ to Arrow
   * timestamp with UTC timezone
   */
  void convertTimestampTZColumn(
    const unsigned int batchIdx,
    const int colIdx,
    const std::shared_ptr<arrow::Field> field,
    const std::shared_ptr<arrow::Array> columnArray,
    const int scale,
    const int byteLength);

  /**
   * convert scaled fixed number to double
   * if scale is small, then just divide based on the scale; otherwise, convert the value to string first and then
   * convert to double to avoid precision loss
   */
  template <typename T>
  double convertScaledFixedNumberToDouble(
    const unsigned int scale,
    T originalValue
  );
};
}
#endif  // PC_ARROWTABLEITERATOR_HPP
