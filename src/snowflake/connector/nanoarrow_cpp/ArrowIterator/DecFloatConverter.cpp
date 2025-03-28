
#include "DecFloatConverter.hpp"

#include <cstring>
#include <memory>

#include "Python/Helpers.hpp"

namespace sf {

Logger* DecFloatConverter::logger =
    new Logger("snowflake.connector.DecFloatConverter");

const std::string DecFloatConverter::FIELD_NAME_EXPONENT = "exponent";
const std::string DecFloatConverter::FIELD_NAME_SIGNIFICAND = "significand";

DecFloatConverter::DecFloatConverter(ArrowArrayView& array,
                                     ArrowSchemaView& schema, PyObject& context,
                                     bool useNumpy)
    : m_context(context),
      m_array(array),
      m_exponent(nullptr),
      m_significand(nullptr),
      m_useNumpy(useNumpy) {
  if (schema.schema->n_children != 2) {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow schema field number does not match, "
        "expected 2 but got %d instead",
        schema.schema->n_children);
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
  }
  for (int i = 0; i < schema.schema->n_children; i += 1) {
    ArrowSchema* c_schema = schema.schema->children[i];
    if (std::strcmp(c_schema->name,
                    DecFloatConverter::FIELD_NAME_EXPONENT.c_str()) == 0) {
      m_exponent = m_array.children[i];
    } else if (std::strcmp(c_schema->name,
                           DecFloatConverter::FIELD_NAME_SIGNIFICAND.c_str()) ==
               0) {
      m_significand = m_array.children[i];
    }
  }
  if (!m_exponent || !m_significand) {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] arrow schema field names do not match, "
        "expected %s and %s, but got %s and %s instead",
        DecFloatConverter::FIELD_NAME_EXPONENT.c_str(),
        DecFloatConverter::FIELD_NAME_SIGNIFICAND.c_str(),
        schema.schema->children[0]->name, schema.schema->children[1]->name);
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return;
  }
}

PyObject* DecFloatConverter::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(&m_array, rowIndex)) {
    Py_RETURN_NONE;
  }
  int64_t exponent = ArrowArrayViewGetIntUnsafe(m_exponent, rowIndex);
  ArrowStringView stringView =
      ArrowArrayViewGetStringUnsafe(m_significand, rowIndex);
  if (stringView.size_bytes > 16) {
    std::string errorInfo = Logger::formatString(
        "[Snowflake Exception] only precisions up to 38 supported. "
        "Please update to a newer version of the connector.");
    logger->error(__FILE__, __func__, __LINE__, errorInfo.c_str());
    PyErr_SetString(PyExc_Exception, errorInfo.c_str());
    return nullptr;
  }
  PyObject* significand =
      PyBytes_FromStringAndSize(stringView.data, stringView.size_bytes);

  PyObject* result = PyObject_CallMethod(
      &m_context,
      m_useNumpy ? "DECFLOAT_to_numpy_float64" : "DECFLOAT_to_decimal", "iS",
      exponent, significand);
  Py_XDECREF(significand);
  return result;
}
}  // namespace sf
