//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#include "ObjectConverter.hpp"

#include <memory>

#include "CArrowChunkIterator.hpp"
#include "CArrowIterator.hpp"
#include "SnowflakeType.hpp"

namespace sf {
Logger* ObjectConverter::logger =
    new Logger("snowflake.connector.BinaryConverter");

ObjectConverter::ObjectConverter(ArrowSchemaView* schemaView,
                                 ArrowArrayView* array, PyObject* context,
                                 bool useNumpy) {
  m_array = array;
  m_converters.clear();
  m_propertyNames.clear();
  m_propertyCount = schemaView->schema->n_children;

  for (int i = 0; i < schemaView->schema->n_children; i++) {
    ArrowSchema* propertySchema = schemaView->schema->children[i];

    m_propertyNames.push_back(propertySchema->name);

    ArrowArrayView* child_array = array->children[i];

    m_converters.push_back(getConverterFromSchema(propertySchema, child_array,
                                                  context, useNumpy, logger));
  }
}

PyObject* ObjectConverter::toPyObject(int64_t rowIndex) const {
  if (ArrowArrayViewIsNull(m_array, rowIndex)) {
    Py_RETURN_NONE;
  }

  PyObject* dict = PyDict_New();
  for (int i = 0; i < m_propertyCount; i++) {
    PyDict_SetItemString(dict, m_propertyNames[i],
                         m_converters[i]->toPyObject(rowIndex));
  }
  return dict;
}

}  // namespace sf
