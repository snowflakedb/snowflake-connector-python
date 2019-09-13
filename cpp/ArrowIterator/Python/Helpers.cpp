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

using Logger = ::sf::Logger;

void importPythonModule(const std::string& moduleName, UniqueRef& ref)
{
  PyObject* module = PyImport_ImportModule(moduleName.c_str());
  if (checkPyError())
  {
    return;
  }
  ref.reset(module);
  return;
}

void importPythonModule(const std::string& moduleName, UniqueRef& ref,
                        Logger& logger)
{
  PyObject* module = PyImport_ImportModule(moduleName.c_str());
  if (checkPyError())
  {
    logger.error("import python module '%s' failed", moduleName.c_str());
    return;
  }
  ref.reset(module);
  return;
}

void importFromModule(const UniqueRef& moduleRef, const std::string& name,
                      UniqueRef& ref)
{
  PyObject* attr = PyObject_GetAttrString(moduleRef.get(), name.c_str());
  if (checkPyError())
  {
    return;
  }
  ref.reset(attr);
  return;
}

void importFromModule(const UniqueRef& moduleRef, const std::string& name,
                      UniqueRef& ref, Logger& logger)
{
  PyObject* attr = PyObject_GetAttrString(moduleRef.get(), name.c_str());
  if (checkPyError())
  {
    logger.error("import python attribute '%s' failed", name.c_str());
    return;
  }
  ref.reset(attr);
  return;
}

}  // namespace py
}  // namespace sf
