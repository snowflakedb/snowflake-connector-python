/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#include "time.hpp"

namespace sf
{

namespace internal
{

int32_t getNumberOfDigit(int32_t num)
{
  return (num >= 100000000)
             ? 9
             : (num >= 10000000)
                   ? 8
                   : (num >= 1000000)
                         ? 7
                         : (num >= 100000)
                               ? 6
                               : (num >= 10000)
                                     ? 5
                                     : (num >= 1000)
                                           ? 4
                                           : (num >= 100) ? 3 : (num >= 10)
                                                                    ? 2
                                                                    : (num >= 1)
                                                                          ? 1
                                                                          : 0;
}

int32_t getHourFromSeconds(int64_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] / SECONDS_PER_HOUR;
}

int32_t getHourFromSeconds(int32_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] / SECONDS_PER_HOUR;
}

int32_t getMinuteFromSeconds(int64_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
}

int32_t getMinuteFromSeconds(int32_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
}

int32_t getSecondFromSeconds(int64_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] % SECONDS_PER_MINUTE;
}

int32_t getSecondFromSeconds(int32_t seconds, int32_t scale)
{
  return seconds / powTenSB4[scale] % SECONDS_PER_MINUTE;
}

int32_t getMicrosecondFromSeconds(int64_t seconds, int32_t scale)
{
  int32_t microsec = seconds % powTenSB4[scale];
  return scale > PYTHON_DATETIME_TIME_MICROSEC_BITS ? microsec /=
         powTenSB4[scale - PYTHON_DATETIME_TIME_MICROSEC_BITS] : microsec *=
         powTenSB4[PYTHON_DATETIME_TIME_MICROSEC_BITS - scale];
}

double secondsToDouble(int64_t seconds, int32_t scale)
{
  return scale > PYTHON_DATETIME_TIME_MICROSEC_BITS
             ? static_cast<double>(
                   seconds /
                   powTenSB4[scale - PYTHON_DATETIME_TIME_MICROSEC_BITS]) /
                   powTenSB4[PYTHON_DATETIME_TIME_MICROSEC_BITS]
             : static_cast<double>(seconds) / powTenSB4[scale];
}

}  // namespace internal
}  // namespace sf
