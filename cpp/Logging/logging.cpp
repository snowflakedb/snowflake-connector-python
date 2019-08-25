#include "logging.hpp"
#include "Python/Helpers.hpp"
#include <cstdio>

namespace sf
{
std::string Logger::formatString(const char *format, ...)
{
  char msg[1000] = {0};
  va_list args;
  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  return std::string(msg);
}

Logger::Logger(const char *name)
{
  py::UniqueRef pyLoggingModule;
  py::importPythonModule("logging", pyLoggingModule);
  PyObject *logger =
      PyObject_CallMethod(pyLoggingModule.get(), "getLogger", "s", name);
  m_pyLogger.reset(logger);
}

void Logger::debug(const char *format, ...)
{
  char msg[1000] = {0};
  va_list args;
  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  PyObject_CallMethod(m_pyLogger.get(), "debug", "s", msg);
}

void Logger::info(const char *format, ...)
{
  char msg[1000] = {0};
  va_list args;
  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  PyObject_CallMethod(m_pyLogger.get(), "info", "s", msg);
}

void Logger::warn(const char *format, ...)
{
  char msg[1000] = {0};
  va_list args;
  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  PyObject_CallMethod(m_pyLogger.get(), "warn", "s", msg);
}

void Logger::error(const char *format, ...)
{
  char msg[1000] = {0};
  va_list args;
  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  PyObject_CallMethod(m_pyLogger.get(), "error", "s", msg);
}
}
