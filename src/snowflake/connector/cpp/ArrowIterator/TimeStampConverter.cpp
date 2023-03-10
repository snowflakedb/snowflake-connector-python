//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "TimeStampConverter.hpp"
#include "Python/Helpers.hpp"
#include "Util/time.hpp"

#include <cstdint>
#include <memory>
#include <type_traits>

template <typename T>
constexpr char toType() {
    static_assert(
        std::is_same<T, signed char>::value
        || std::is_same<T, short>::value
        || std::is_same<T, int>::value
        || std::is_same<T, long>::value
        || std::is_same<T, long long>::value
    , "Unknown type");
    return std::is_same<T, signed char>::value ? 'b'
    : std::is_same<T, short>::value ? 'h'
    : std::is_same<T, int>::value ? 'i'
    : std::is_same<T, long>::value ? 'l'
    : std::is_same<T, long long>::value ? 'L'
    // Should not get here. Error.
    : '?';
}

template <typename T1>
struct FormatArgs1 {
  char format[2];
  constexpr FormatArgs1()
  : format{toType<T1>(), '\0'}
  {}
};
template <typename T1, typename T2>
struct FormatArgs2 {
  char format[3];
  constexpr FormatArgs2()
  : format{toType<T1>(), toType<T2>(), '\0'}
  {}
};
template <typename T1, typename T2, typename T3>
struct FormatArgs3 {
  char format[4];
  constexpr FormatArgs3()
  : format{toType<T1>(), toType<T2>(), toType<T3>(), '\0'}
  {}
};

namespace sf
{
TimeStampBaseConverter::TimeStampBaseConverter(PyObject* context, int32_t scale)
: m_context(context), m_scale(scale)
{
}

OneFieldTimeStampNTZConverter::OneFieldTimeStampNTZConverter(
    std::shared_ptr<ArrowArrayView> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(array)
{
}

PyObject* OneFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array.get(), rowIndex);
  internal::TimeSpec ts(val, m_scale);

  static constexpr FormatArgs2<decltype(ts.seconds), decltype(ts.microseconds)> format;
#ifdef _WIN32
  return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python_windows", format.format,
                               ts.seconds, ts.microseconds);
#else
  return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python", format.format,
                               ts.seconds, ts.microseconds);
#endif
}

NumpyOneFieldTimeStampNTZConverter::NumpyOneFieldTimeStampNTZConverter(
    std::shared_ptr<ArrowArrayView> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(array)
{
}

PyObject* NumpyOneFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array.get(), rowIndex);
  return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_ONE_FIELD_to_numpy_datetime64", "Li", val, m_scale);
}

TwoFieldTimeStampNTZConverter::TwoFieldTimeStampNTZConverter(
    std::shared_ptr<ArrowArrayView> array, std::shared_ptr<ArrowSchemaView> schema, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_schema(schema), m_array(array)
{
    if (m_schema->schema->n_children != 2) {
        // TODO raise error
    }
    for(int i = 0; i < m_schema->schema->n_children; i += 1) {
        ArrowSchema* c_schema = m_schema->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            m_epoch = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0){
            m_fraction = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else {
            //TODO raise error: unrecognized fields
        }
    }
}

PyObject* TwoFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
      Py_RETURN_NONE;
  }
    int64_t seconds = ArrowArrayViewGetIntUnsafe(m_epoch.get(), rowIndex);
    int64_t microseconds = ArrowArrayViewGetIntUnsafe(m_fraction.get(), rowIndex) / 1000;

    static constexpr FormatArgs2<decltype(seconds), decltype(microseconds)> format;
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python_windows", format.format,
                               seconds, microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_to_python", format.format,
                               seconds, microseconds);
#endif
}

NumpyTwoFieldTimeStampNTZConverter::NumpyTwoFieldTimeStampNTZConverter(
    std::shared_ptr<ArrowArrayView> array, std::shared_ptr<ArrowSchemaView> schema, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_schema(schema), m_array(array)
{
    if (m_schema->schema->n_children != 2) {
        // TODO raise error
    }
    for(int i = 0; i < m_schema->schema->n_children; i += 1) {
        ArrowSchema* c_schema = m_schema->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            m_epoch = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0){
            m_fraction = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else {
            //TODO raise error: unrecognized fields
        }
    }
}

PyObject* NumpyTwoFieldTimeStampNTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
      Py_RETURN_NONE;
  }
    int64_t epoch = ArrowArrayViewGetIntUnsafe(m_epoch.get(), rowIndex);
    int32_t frac = ArrowArrayViewGetIntUnsafe(m_fraction.get(), rowIndex);
    return PyObject_CallMethod(m_context, "TIMESTAMP_NTZ_TWO_FIELD_to_numpy_datetime64", "Li", epoch, frac);
}


OneFieldTimeStampLTZConverter::OneFieldTimeStampLTZConverter(
    std::shared_ptr<ArrowArrayView> array, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_array(array)
{
}

PyObject* OneFieldTimeStampLTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t val = ArrowArrayViewGetIntUnsafe(m_array.get(), rowIndex);
  internal::TimeSpec ts(val, m_scale);

  static constexpr FormatArgs2<decltype(ts.seconds), decltype(ts.microseconds)> format;

#ifdef _WIN32
      return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python_windows", format.format,
                                   ts.seconds, ts.microseconds);
#else
      return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python", format.format,
                                   ts.seconds, ts.microseconds);
#endif
}

TwoFieldTimeStampLTZConverter::TwoFieldTimeStampLTZConverter(
    std::shared_ptr<ArrowArrayView> array, std::shared_ptr<ArrowSchemaView> schema, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_schema(schema), m_array(array)
{
    if (m_schema->schema->n_children != 2) {
        // TODO raise error
    }
    for(int i = 0; i < m_schema->schema->n_children; i += 1) {
        ArrowSchema* c_schema = m_schema->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            m_epoch = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0){
            m_fraction = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else {
            //TODO raise error: unrecognized fields
        }
    }
}

PyObject* TwoFieldTimeStampLTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
      Py_RETURN_NONE;
  }
    int64_t seconds = ArrowArrayViewGetIntUnsafe(m_epoch.get(), rowIndex);
    int64_t microseconds = ArrowArrayViewGetIntUnsafe(m_fraction.get(), rowIndex) / 1000;

    static constexpr FormatArgs2<decltype(seconds), decltype(microseconds)> format;
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python_windows", format.format,
                               seconds, microseconds);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_LTZ_to_python", format.format,
                               seconds, microseconds);
#endif
}

TwoFieldTimeStampTZConverter::TwoFieldTimeStampTZConverter(
    std::shared_ptr<ArrowArrayView> array, std::shared_ptr<ArrowSchemaView> schema, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_schema(schema), m_array(array)
{
    if (m_schema->schema->n_children != 2) {
        // TODO raise error
    }
    for(int i = 0; i < m_schema->schema->n_children; i += 1) {
        ArrowSchema* c_schema = m_schema->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            m_epoch = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_TIME_ZONE.c_str()) == 0){
            m_timezone = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else {
            //TODO raise error: unrecognized fields
        }
    }
}

PyObject* TwoFieldTimeStampTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
      Py_RETURN_NONE;
  }

    int32_t timezone = ArrowArrayViewGetIntUnsafe(m_timezone.get(), rowIndex);
    internal::TimeSpec ts(ArrowArrayViewGetIntUnsafe(m_epoch.get(), rowIndex), m_scale);

    static constexpr FormatArgs3<decltype(ts.seconds), decltype(ts.microseconds), decltype(timezone)> format;
#if _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python_windows", format.format,
                               ts.seconds, ts.microseconds, timezone);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python", format.format,
                               ts.seconds, ts.microseconds, timezone);
#endif
}

ThreeFieldTimeStampTZConverter::ThreeFieldTimeStampTZConverter(
    std::shared_ptr<ArrowArrayView> array, std::shared_ptr<ArrowSchemaView> schema, int32_t scale, PyObject* context)
: TimeStampBaseConverter(context, scale),
  m_schema(schema), m_array(array)
{
    if (m_schema->schema->n_children != 3) {
        // TODO raise error
    }
    for(int i = 0; i < m_schema->schema->n_children; i += 1) {
        ArrowSchema* c_schema = m_schema->schema->children[i];
        if(std::strcmp(c_schema->name, internal::FIELD_NAME_EPOCH.c_str()) == 0) {
            m_epoch = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_TIME_ZONE.c_str()) == 0){
            m_timezone = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else if(std::strcmp(c_schema->name, internal::FIELD_NAME_FRACTION.c_str()) == 0){
            m_fraction = std::shared_ptr<ArrowArrayView>(m_array->children[i]);
        } else {
            //TODO raise error: unrecognized fields
        }
    }
}

PyObject* ThreeFieldTimeStampTZConverter::toPyObject(int64_t rowIndex) const
{
  if(ArrowArrayViewIsNull(m_array.get(), rowIndex)) {
      Py_RETURN_NONE;
  }

    int32_t timezone = ArrowArrayViewGetIntUnsafe(m_timezone.get(), rowIndex);
    int64_t seconds = ArrowArrayViewGetIntUnsafe(m_epoch.get(), rowIndex);
    int64_t microseconds = ArrowArrayViewGetIntUnsafe(m_fraction.get(), rowIndex) / 1000;

    static constexpr FormatArgs3<decltype(seconds), decltype(microseconds), decltype(timezone)> format;
#ifdef _WIN32
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python_windows", format.format,
                               seconds, microseconds, timezone);
#else
    return PyObject_CallMethod(m_context, "TIMESTAMP_TZ_to_python", format.format,
                               seconds, microseconds, timezone);
#endif
}

}  // namespace sf
