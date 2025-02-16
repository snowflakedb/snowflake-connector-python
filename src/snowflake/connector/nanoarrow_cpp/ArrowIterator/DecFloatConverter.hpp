
//
// Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
//

#ifndef PC_DECFLOATCONVERTER_HPP
#define PC_DECFLOATCONVERTER_HPP

#include <memory>

#include "IColumnConverter.hpp"
#include "logging.hpp"
#include "nanoarrow.h"

namespace sf {

class DecFloatConverter : public IColumnConverter {
 public:
  const std::string FIELD_NAME_EXPONENT = "exponent";
  const std::string FIELD_NAME_SIGNIFICAND = "significand";

  explicit DecFloatConverter(ArrowArrayView& array, ArrowSchemaView& schema,
                             PyObject& context, bool useNumpy);

  PyObject* toPyObject(int64_t rowIndex) const override;

 private:
  PyObject& m_context;
  ArrowArrayView& m_array;
  ArrowArrayView* m_exponent;
  ArrowArrayView* m_significand;
  bool m_useNumpy;

  static Logger* logger;
};

}  // namespace sf

#endif  // PC_DECFLOATCONVERTER_HPP
