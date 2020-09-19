//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

#ifndef PC_PYTHON_HELPERS_HPP
#define PC_PYTHON_HELPERS_HPP

/** this two header files will be removed when we replace arrow::Status with our
 * own status data structure */
#include <arrow/python/platform.h>
#include <arrow/api.h>
#include "logging.hpp"

namespace sf
{

namespace py
{

class UniqueRef;

using Logger = ::sf::Logger;

/** All arrow::Status will be replaced by our own data structure in the future
 */

/**
 * \brief: import a python module
 * \param moduleName: the name of the python module
 * \param ref: the RAII object to manage the PyObject
 * \return:
 */
void importPythonModule(const std::string& moduleName, UniqueRef& ref);

void importPythonModule(const std::string& moduleName, UniqueRef& ref,
                        const Logger& logger);

void importFromModule(const UniqueRef& moduleRef, const std::string& name,
                      UniqueRef& ref);

void importFromModule(const UniqueRef& moduleRef, const std::string& name,
                      UniqueRef& ref, const Logger& logger);

}  // namespace py
}  // namespace sf

#endif  // PC_PYTHON_HELPERS_HPP
