//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#include "TimeStampConverter.hpp"
#include "Python/Helpers.hpp"
#include "Util/time.hpp"

namespace sf
{
TimeStampBaseConverter::TimeStampBaseConverter(PyObject* context, int32_t scale)
: m_context(context), m_scale(scale)
{
}

OneFieldTimeStampNTZConverter::OneFieldTimeStampNTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::Int64Array>(array))
{
}

PyObject* OneFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    double microseconds = internal::getFormattedDoubleFromEpoch(
        m_array->Value(rowIndex), m_scale);
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python_windows",
                               "d", microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python", "d",
                               microseconds);
#endif
  }
  else
  {
    Py_RETURN_NONE;
  }
}

NumpyOneFieldTimeStampNTZConverter::NumpyOneFieldTimeStampNTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::Int64Array>(array))
{
}

PyObject* NumpyOneFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t val = m_array->Value(rowIndex);
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_ONE_FIELD_to_numpy_datetime64", "Li", val, m_scale);
  }
  else
  {
    Py_RETURN_NONE;
  }
}

TwoFieldTimeStampNTZConverter::TwoFieldTimeStampNTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::StructArray>(array)),
  m_epoch(std::dynamic_pointer_cast<arrow::Int64Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_EPOCH))),
  m_fraction(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_FRACTION)))
{
}

PyObject* TwoFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t epoch = m_epoch->Value(rowIndex);
    int32_t frac = m_fraction->Value(rowIndex);
    double microseconds =
        internal::getFormattedDoubleFromEpochFraction(epoch, frac, m_scale);
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python_windows",
                               "d", microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python", "d",
                               microseconds);
#endif
  }
  else
  {
    Py_RETURN_NONE;
  }
}

NumpyTwoFieldTimeStampNTZConverter::NumpyTwoFieldTimeStampNTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::StructArray>(array)),
  m_epoch(std::dynamic_pointer_cast<arrow::Int64Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_EPOCH))),
  m_fraction(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_FRACTION)))
{
}

PyObject* NumpyTwoFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t epoch = m_epoch->Value(rowIndex);
    int32_t frac = m_fraction->Value(rowIndex);
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_TWO_FIELD_to_numpy_datetime64", "Li", epoch, frac);
  }
  else
  {
    Py_RETURN_NONE;
  }
}


OneFieldTimeStampLTZConverter::OneFieldTimeStampLTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::Int64Array>(array))
{
}

PyObject* OneFieldTimeStampLTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    double microseconds = internal::getFormattedDoubleFromEpoch(
        m_array->Value(rowIndex), m_scale);
#ifdef _WIN32
    // this macro is enough for both win32 and win64
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python_windows",
                               "d", microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python", "d",
                               microseconds);
#endif
  }

  Py_RETURN_NONE;
}

TwoFieldTimeStampLTZConverter::TwoFieldTimeStampLTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::StructArray>(array)),
  m_epoch(std::dynamic_pointer_cast<arrow::Int64Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_EPOCH))),
  m_fraction(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_FRACTION)))
{
}

PyObject* TwoFieldTimeStampLTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t epoch = m_epoch->Value(rowIndex);
    int32_t frac = m_fraction->Value(rowIndex);
    double microseconds =
        internal::getFormattedDoubleFromEpochFraction(epoch, frac, m_scale);
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python_windows",
                               "d", microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python", "d",
                               microseconds);
#endif
  }

  Py_RETURN_NONE;
}

TwoFieldTimeStampTZConverter::TwoFieldTimeStampTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::StructArray>(array)),
  m_epoch(std::dynamic_pointer_cast<arrow::Int64Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_EPOCH))),
  m_timezone(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_TIME_ZONE)))
{
}

PyObject* TwoFieldTimeStampTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t epoch = m_epoch->Value(rowIndex);
    double microseconds = internal::getFormattedDoubleFromEpoch(epoch, m_scale);
    int32_t timezone = m_timezone->Value(rowIndex);
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python_windows",
                               "di", microseconds, timezone);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python", "di",
                               microseconds, timezone);
#endif
  }

  Py_RETURN_NONE;
}

ThreeFieldTimeStampTZConverter::ThreeFieldTimeStampTZConverter(
    std::shared_ptr<arrow::Array> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(std::dynamic_pointer_cast<arrow::StructArray>(array)),
  m_epoch(std::dynamic_pointer_cast<arrow::Int64Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_EPOCH))),
  m_timezone(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_TIME_ZONE))),
  m_fraction(std::dynamic_pointer_cast<arrow::Int32Array>(
      m_array->GetFieldByName(internal::FIELD_NAME_FRACTION)))
{
}

PyObject* ThreeFieldTimeStampTZConverter::toPyObject(int64_t rowIndex) const
{
  if (m_array->IsValid(rowIndex))
  {
    int64_t epoch = m_epoch->Value(rowIndex);
    int32_t frac = m_fraction->Value(rowIndex);
    double microseconds =
        internal::getFormattedDoubleFromEpochFraction(epoch, frac, m_scale);
    int32_t timezone = m_timezone->Value(rowIndex);
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python_windows",
                               "di", microseconds, timezone);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python", "di",
                               microseconds, timezone);
#endif
  }

  Py_RETURN_NONE;
}

}  // namespace sf
