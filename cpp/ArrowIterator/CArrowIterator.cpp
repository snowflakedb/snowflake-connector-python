/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */

#include "CArrowIterator.hpp"

namespace sf
{

Logger CArrowIterator::logger("snowflake.connector.CArrowIterator");

CArrowIterator::CArrowIterator(PyObject* batches)
{
  int pyListSize = PyList_Size(batches);
  logger.debug("Arrow BatchSize: %d", pyListSize);

  for (int i=0; i<pyListSize; i++)
  {
    std::shared_ptr<arrow::RecordBatch> cRecordBatch;
    arrow::Status status = arrow::py::unwrap_record_batch(PyList_GetItem(batches, i), &cRecordBatch);
    m_cRecordBatches.push_back(cRecordBatch);
  }
}

}
