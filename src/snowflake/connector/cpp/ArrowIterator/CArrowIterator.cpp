//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#include "CArrowIterator.hpp"

namespace sf
{

Logger* CArrowIterator::logger = new Logger("snowflake.connector.CArrowIterator");

CArrowIterator::CArrowIterator(std::vector<std::shared_ptr<arrow::RecordBatch>>* batches) :
  m_cRecordBatches(batches)
{
  logger->debug(__FILE__, __func__, __LINE__, "Arrow BatchSize: %d", batches->size());
}

}
