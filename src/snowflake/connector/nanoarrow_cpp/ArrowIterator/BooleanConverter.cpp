#include "BooleanConverter.hpp"

#include <memory>

namespace sf {

BooleanConverter::BooleanConverter(ArrowArrayView* array) : m_array(array) {}

PyObject* BooleanConverter::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }

  if (ArrowArrayViewGetIntUnsafe(m_array, rowIndex)) {
    Py_RETURN_TRUE;
  } else {
    Py_RETURN_FALSE;
  }
}

}  // namespace sf
