/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include <Python.h>
#include "Helpers.hpp"
#include "Common.hpp"

namespace sf
{

namespace py
{

arrow::Status importPythonModule(const std::string& moduleName, UniqueRef& ref)
{
    PyObject* module = PyImport_ImportModule(moduleName.c_str());
    // TODO : to check the function call's status, whether it is success
    ref.reset(module);
    return arrow::Status::OK();
}

arrow::Status importFromModule(const UniqueRef& moduleRef, const std::string& name, UniqueRef& ref)
{
    PyObject* attr = PyObject_GetAttrString(moduleRef.get(), name.c_str());
    // TODO : to check the function call's status, whether it is success
    ref.reset(attr);
    return arrow::Status::OK();
}

} // namespace py
} // namespace sf
