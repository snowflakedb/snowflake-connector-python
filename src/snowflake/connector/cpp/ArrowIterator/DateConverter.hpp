//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_DATECONVERTER_HPP
#define PC_DATECONVERTER_HPP

#include "IColumnConverter.hpp"
#include "Python/Common.hpp"
#include "logging.hpp"
#include "nanoarrow.h"
#include <memory>

namespace sf
{

class DateConverter : public IColumnConverter
{
public:
  explicit DateConverter(std::shared_ptr<ArrowArrayView> array);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  static py::UniqueRef& initPyDatetimeDate();

  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  /** from Python Ordinal to 1970-01-01 */
  static constexpr int epochDay = 719163;

  static Logger* logger;

  py::UniqueRef& m_pyDatetimeDate;
};

class NumpyDateConverter : public IColumnConverter
{
public:
  explicit NumpyDateConverter(std::shared_ptr<ArrowArrayView> array, PyObject * context);

  PyObject* toPyObject(int64_t rowIndex) const override;

private:
  std::shared_ptr<ArrowArrayView> m_nanoarrowArrayView;

  PyObject * m_context;
};

}  // namespace sf

#endif  // PC_DATECONVERTER_HPP
