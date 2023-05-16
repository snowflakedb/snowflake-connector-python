//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "CArrowIterator.hpp"
#include "nanoarrow.h"
#include "nanoarrow_ipc.h"
#include <memory>

namespace sf
{

Logger* CArrowIterator::logger = new Logger("snowflake.connector.CArrowIterator");

CArrowIterator::CArrowIterator(char* arrow_bytes, int64_t arrow_bytes_size)
{

  ArrowBuffer input_buffer;
  ArrowBufferInit(&input_buffer);
  ArrowBufferAppend(&input_buffer, arrow_bytes, arrow_bytes_size);
  ArrowIpcInputStream input;
  ArrowIpcInputStreamInitBuffer(&input, &input_buffer);
  ArrowArrayStream stream;
  ArrowIpcArrayStreamReaderInit(&stream, &input, nullptr);
  stream.get_schema(&stream, m_ipcArrowSchema.get());

  while(true) {
    nanoarrow::UniqueArray newUniqueArray;
    nanoarrow::UniqueArrayView newUniqueArrayView;
    auto retcode = stream.get_next(&stream, newUniqueArray.get());
    if(retcode == NANOARROW_OK && newUniqueArray->release != nullptr) {
      m_ipcArrowArrayVec.push_back(std::move(newUniqueArray));

      ArrowError error;
      int returnCode = ArrowArrayViewInitFromSchema(
      newUniqueArrayView.get(), m_ipcArrowSchema.get(), &error);
      if (returnCode != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] error initializing ArrowArrayView from schema : %s",
          ArrowErrorMessage(&error)
        );
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      }

      returnCode = ArrowArrayViewSetArray(
        newUniqueArrayView.get(), newUniqueArray.get(), &error);
      if (returnCode != NANOARROW_OK) {
        std::string errorInfo = Logger::formatString(
          "[Snowflake Exception] error setting ArrowArrayView from array : %s",
          ArrowErrorMessage(&error)
        );
        logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
        PyErr_SetString(PyExc_Exception, errorInfo.c_str());
      }
      m_ipcArrowArrayViewVec.push_back(std::move(newUniqueArrayView));
    } else {
      break;
    }
  }
  stream.release(&stream);
  logger->debug(__FILE__, __func__, __LINE__, "Arrow BatchSize: %d", m_ipcArrowArrayVec.size());
}

}
