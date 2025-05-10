#ifndef PC_INTERVALCONVERTER_HPP
#define PC_INTERVALCONVERTER_HPP

#include <memory>

#include "IColumnConverter.hpp"
#include "nanoarrow.h"
#include "nanoarrow.hpp"

namespace sf {

class IntervalYearMonthConverter : public IColumnConverter {
 public:
  explicit IntervalYearMonthConverter(ArrowArrayView* array, PyObject* context,
                                      bool useNumpy);
  virtual ~IntervalYearMonthConverter() = default;

  PyObject* toPyObject(int64_t rowIndex) const override;

 private:
  ArrowArrayView* m_array;
  PyObject* m_context;
  bool m_useNumpy;
};

class IntervalDayTimeConverterInt : public IColumnConverter {
 public:
  explicit IntervalDayTimeConverterInt(ArrowArrayView* array, PyObject* context,
                                       bool useNumpy);
  virtual ~IntervalDayTimeConverterInt() = default;

  PyObject* toPyObject(int64_t rowIndex) const override;

 private:
  ArrowArrayView* m_array;
  PyObject* m_context;
  const char* m_method;
};

class IntervalDayTimeConverterDecimal : public IColumnConverter {
 public:
  explicit IntervalDayTimeConverterDecimal(ArrowArrayView* array,
                                           PyObject* context, bool useNumpy);
  virtual ~IntervalDayTimeConverterDecimal() = default;

  PyObject* toPyObject(int64_t rowIndex) const override;

 private:
  ArrowArrayView* m_array;
  PyObject* m_context;
  const char* m_method;
};

}  // namespace sf

#endif  // PC_INTERVALCONVERTER_HPP
