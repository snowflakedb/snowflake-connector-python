#ifndef PC_LOGGING_HPP
#define PC_LOGGING_HPP

#include <mutex>
#include <string>

#include "Python/Common.hpp"

namespace sf {

class Logger {
 public:
  explicit Logger(const char *name);

  void log(int level, const char *path_name, const char *func_name,
           int line_num, const char *msg);

  void debug(const char *path_name, const char *func_name, int line_num,
             const char *format, ...);

  void info(const char *path_name, const char *func_name, int line_num,
            const char *format, ...);

  void warn(const char *path_name, const char *func_name, int line_num,
            const char *format, ...);

  void error(const char *path_name, const char *func_name, int line_num,
             const char *format, ...);

  static std::string formatString(const char *fmt, ...);

 private:
  py::UniqueRef m_pyLogger;
  // Serializes the one-time lazy initialization of m_pyLogger inside log().
  // Without this, on Python 3.13t/3.14t (--disable-gil) two threads racing
  // the first call to log() could both observe m_pyLogger.empty() and both
  // invoke setupPyLogger(), torn-writing the pointer and leaking one of the
  // PyLogger objects.
  std::once_flag m_initOnceFlag;
  const char *const m_name;
  static constexpr int CRITICAL = 50;
  static constexpr int FATAL = CRITICAL;
  static constexpr int ERROR = 40;
  static constexpr int WARNING = 30;
  static constexpr int WARN = WARNING;
  static constexpr int INFO = 20;
  static constexpr int DEBUG = 10;
  static constexpr int NOTSET = 0;
  static constexpr int LINE_NUM = 0;

  void setupPyLogger();
};

}  // namespace sf

#endif  // PC_LOGGING_HPP
