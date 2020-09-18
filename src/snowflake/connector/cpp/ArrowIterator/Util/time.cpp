//
// Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
//

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
  return scale > PYTHON_DATETIME_TIME_MICROSEC_DIGIT ? microsec /=
         powTenSB4[scale - PYTHON_DATETIME_TIME_MICROSEC_DIGIT] : microsec *=
         powTenSB4[PYTHON_DATETIME_TIME_MICROSEC_DIGIT - scale];
}

double getFormattedDoubleFromEpoch(int64_t epoch, int32_t scale)
{
  return scale > PYTHON_DATETIME_TIME_MICROSEC_DIGIT
             ? static_cast<double>(
                   epoch /
                   powTenSB4[scale - PYTHON_DATETIME_TIME_MICROSEC_DIGIT]) /
                   powTenSB4[PYTHON_DATETIME_TIME_MICROSEC_DIGIT]
             : static_cast<double>(epoch) / powTenSB4[scale];
}

double getFormattedDoubleFromEpochFraction(int64_t epoch, int32_t frac,
                                           int32_t scale)
{
  return static_cast<double>(epoch) +
         static_cast<double>(castToFormattedFraction(frac, epoch < 0, scale)) /
             powTenSB4[std::min(scale, PYTHON_DATETIME_TIME_MICROSEC_DIGIT)];
}

int32_t castToFormattedFraction(int32_t frac, bool isNegative, int32_t scale)
{
  // if scale > 6 or not
  constexpr int DIFF_DIGIT =
      NANOSEC_DIGIT - PYTHON_DATETIME_TIME_MICROSEC_DIGIT;
  if (scale > 6)
  {
    return !isNegative
               ? (frac / powTenSB4[DIFF_DIGIT])
               : (powTenSB4[PYTHON_DATETIME_TIME_MICROSEC_DIGIT] -
                  (powTenSB4[NANOSEC_DIGIT] - frac) / powTenSB4[DIFF_DIGIT]);
  }
  else
  {
    return !isNegative
               ? (frac / powTenSB4[NANOSEC_DIGIT - scale])
               : (powTenSB4[scale] - (powTenSB4[NANOSEC_DIGIT] - frac) /
                                         powTenSB4[NANOSEC_DIGIT - scale]);
  }
}

}  // namespace internal
}  // namespace sf
