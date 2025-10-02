#include "IntervalConverter.hpp"

#include <memory>
#include <string>

#include "Python/Common.hpp"
#include "Python/Helpers.hpp"

namespace sf {

static constexpr char INTERVAL_DT_DECIMAL_TO_NUMPY_TIMEDELTA[] =
    "INTERVAL_DAY_TIME_decimal_to_numpy_timedelta";
static constexpr char INTERVAL_DT_DECIMAL_TO_TIMEDELTA[] =
    "INTERVAL_DAY_TIME_decimal_to_timedelta";
static constexpr char INTERVAL_DT_INT_TO_NUMPY_TIMEDELTA[] =
    "INTERVAL_DAY_TIME_int_to_numpy_timedelta";
static constexpr char INTERVAL_DT_INT_TO_TIMEDELTA[] =
    "INTERVAL_DAY_TIME_int_to_timedelta";
static constexpr char INTERVAL_YEAR_MONTH_TO_NUMPY_TIMEDELTA[] =
    "INTERVAL_YEAR_MONTH_to_numpy_timedelta";
// Python timedelta does not support year-month intervals. Use ANSI SQL
// formatted string instead.
static constexpr char INTERVAL_YEAR_MONTH_TO_STR[] =
    "INTERVAL_YEAR_MONTH_to_str";

IntervalYearMonthConverter::IntervalYearMonthConverter(ArrowArrayView* array,
                                                       PyObject* context,
                                                       bool useNumpy)
    : m_array(array), m_context(context) {
  m_method = useNumpy ? INTERVAL_YEAR_MONTH_TO_NUMPY_TIMEDELTA
                      : INTERVAL_YEAR_MONTH_TO_STR;
}

PyObject* IntervalYearMonthConverter::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array, rowIndex);
  return PyObject_CallMethod(m_context, m_method, "L", val);
}

IntervalDayTimeConverterInt::IntervalDayTimeConverterInt(ArrowArrayView* array,
                                                         PyObject* context,
                                                         bool useNumpy)
    : m_array(array), m_context(context) {
  m_method = useNumpy ? INTERVAL_DT_INT_TO_NUMPY_TIMEDELTA
                      : INTERVAL_DT_INT_TO_TIMEDELTA;
}

PyObject* IntervalDayTimeConverterInt::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array, rowIndex);
  return PyObject_CallMethod(m_context, m_method, "L", val);
}

IntervalDayTimeConverterDecimal::IntervalDayTimeConverterDecimal(
    ArrowArrayView* array, PyObject* context, bool useNumpy)
    : m_array(array), m_context(context) {
  m_method = useNumpy ? INTERVAL_DT_DECIMAL_TO_NUMPY_TIMEDELTA
                      : INTERVAL_DT_DECIMAL_TO_TIMEDELTA;
}

PyObject* IntervalDayTimeConverterDecimal::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t bytes_start = 16 * (m_array->array->offset + rowIndex);
  const char* ptr_start = m_array->buffer_views[1].data.as_char;
  PyObject* int128_bytes =
      PyBytes_FromStringAndSize(&(ptr_start[bytes_start]), 16);
  return PyObject_CallMethod(m_context, m_method, "S", int128_bytes);
}
}  // namespace sf
