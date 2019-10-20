/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */

#include "CArrowIterator.hpp"

namespace sf
{

Logger CArrowIterator::logger("snowflake.connector.CArrowIterator");

CArrowIterator::CArrowIterator(std::vector<std::shared_ptr<arrow::RecordBatch>>* batches) :
  m_cRecordBatches(batches)
{
  logger.debug("Arrow BatchSize: %d", batches->size());
}

}
