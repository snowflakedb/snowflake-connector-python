/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */

#include "CArrowIterator.hpp"

namespace sf
{

Logger CArrowIterator::logger("snowflake.connector.CArrowIterator");

void CArrowIterator::addRecordBatch(PyObject* rb)
{
  std::shared_ptr<arrow::RecordBatch> cRecordBatch;
  arrow::Status status = arrow::py::unwrap_record_batch(rb, &cRecordBatch);
  m_cRecordBatches.push_back(cRecordBatch);
}

}