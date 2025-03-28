#ifndef PC_ARROWCHUNKITERATOR_HPP
#define PC_ARROWCHUNKITERATOR_HPP

#include <memory>
#include <vector>

#include "CArrowIterator.hpp"
#include "IColumnConverter.hpp"
#include "Python/Common.hpp"
#include "SnowflakeType.hpp"
#include "logging.hpp"
#include "nanoarrow.h"
#include "nanoarrow.hpp"

namespace sf {

std::shared_ptr<sf::IColumnConverter> getConverterFromSchema(
    ArrowSchema* schema, ArrowArrayView* array, PyObject* context,
    bool useNumpy, Logger* logger);

/**
 * Arrow chunk iterator implementation in C++. The caller (python arrow chunk
 * iterator object)
 * will ask for nextRow to be returned back to Python
 */
class CArrowChunkIterator : public CArrowIterator {
 public:
  /**
   * Constructor
   */
  CArrowChunkIterator(PyObject* context, char* arrow_bytes,
                      int64_t arrow_bytes_size, PyObject* use_numpy,
                      PyObject* check_error_on_every_column);

  /**
   * Destructor
   */
  virtual ~CArrowChunkIterator() = default;

  /**
   * @return a python tuple object which contains all data in current row
   */
  ReturnVal next() override;

 protected:
  /**
   * @return python object of tuple which is tuple of all row values
   */
  virtual void createRowPyObject();

  /** pointer to the latest returned python tuple(row) result */
  py::UniqueRef m_latestReturnedRow;

  /** list of column converters*/
  std::vector<std::shared_ptr<sf::IColumnConverter>> m_currentBatchConverters;
  /** row index inside current record batch (start from 0) */
  int m_rowIndexInBatch;

 private:
  /** number of columns */
  int m_columnCount;

  /** number of record batch in current chunk */
  int m_batchCount;

  /** current index that iterator points to */
  int m_currentBatchIndex;

  /** total number of rows inside current record batch */
  int64_t m_rowCountInBatch;

  /** arrow format convert context for the current session */
  PyObject* m_context;

  /** true if return numpy int64 float64 datetime*/
  bool m_useNumpy;

  /** a flag that ensures running py::checkPyError after each column processing
   * in order to fail early on first python processing error */
  bool m_checkErrorOnEveryColumn;

  void initColumnConverters();
};

class DictCArrowChunkIterator : public CArrowChunkIterator {
 public:
  DictCArrowChunkIterator(PyObject* context, char* arrow_bytes,
                          int64_t arrow_bytes_size, PyObject* use_numpy);

  ~DictCArrowChunkIterator() = default;

 private:
  void createRowPyObject() override;
};

}  // namespace sf

#endif  // PC_ARROWCHUNKITERATOR_HPP
