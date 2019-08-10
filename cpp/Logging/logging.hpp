/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_LOGGING_HPP
#define PC_LOGGING_HPP

#include "Python/Helpers.hpp"
#include "Python/Common.hpp"

namespace sf
{

class Logger
{
public:
  explicit Logger(const char *name);

  void debug(const char *fmt, ...);

  void info(const char *fmt, ...);

  void warn(const char *fmt, ...);

  void error(const char *fmt, ...);

private:
  py::UniqueRef m_pyLogger;
};

}  // namespace sf

#endif  // PC_LOGGING_HPP
