/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_PYTHON_HELPERS_HPP
#define PC_PYTHON_HELPERS_HPP

/** this two header files will be removed when we replace arrow::Status with our own status data structure */
#include <arrow/python/platform.h>
#include <arrow/api.h>

namespace sf
{

namespace py
{

class UniqueRef;

/** All arrow::Status will be replaced by our own data structure in the future */

/**
 * \brief: import a python module
 * \param moduleName: the name of the python module
 * \param ref: the RAII object to manage the PyObject
 * \return: 
 */
arrow::Status importPythonModule(const std::string& moduleName, UniqueRef& ref);

arrow::Status importFromModule(const UniqueRef& moduleRef, const std::string& name, UniqueRef& ref);

} // namespace py
} // namespace sf

#endif // PC_PYTHON_HELPERS_HPP
