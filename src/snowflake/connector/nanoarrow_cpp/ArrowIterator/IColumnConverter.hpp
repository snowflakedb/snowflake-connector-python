#ifndef PC_ICOLUMNCONVERTER_HPP
#define PC_ICOLUMNCONVERTER_HPP

#include "Python/Common.hpp"

namespace sf {

class IColumnConverter {
 public:
  IColumnConverter() = default;
  virtual ~IColumnConverter() = default;
  // The caller is responsible for calling DECREF on the returned pointer
  virtual PyObject* toPyObject(int64_t rowIndex) const = 0;
};
}  // namespace sf

#endif  // PC_ICOLUMNCONVERTER_HPP
