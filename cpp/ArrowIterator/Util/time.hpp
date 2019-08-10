/*
 * Copyright (c) 2013-2019 Snowflake Computing
 */
#ifndef PC_UTIL_TIME_HPP
#define PC_UTIL_TIME_HPP

#include <Python.h>
#include <string>

#ifdef _WIN32
#include <algorithm>
#endif

namespace sf
{

namespace internal
{

constexpr int SECONDS_PER_MINUTE = 60;
constexpr int MINUTES_PER_HOUR = 60;
constexpr int HOURS_PER_DAY = 24;
constexpr int SECONDS_PER_HOUR = MINUTES_PER_HOUR * SECONDS_PER_MINUTE;

constexpr int PYTHON_DATETIME_TIME_MICROSEC_BITS = 6;

constexpr int powTenSB4[]{1,      10,      100,      1000,      10000,
                          100000, 1000000, 10000000, 100000000, 1000000000};

/** if we use c++17 some day in the future, we can use 'constexpr
 * std::string_view sv = "hello, world";' to replace this */
const std::string FIELD_NAME_EPOCH = "epoch";
const std::string FIELD_NAME_TIME_ZONE = "timezone";
const std::string FIELD_NAME_FRACTION = "fraction";

/** pow10Int means the return value should be int type. So user needs to take
 * care not to cause int overflow by a huge parameter n.
 * And since we are using -stdc++11 now, we can only use constexpr in this way.
 * When we move to -stdc++14, we can have a more elegant way, e.g., loop. */
constexpr int pow10Int(int n)
{
  return n == 0 ? 1 : 10 * pow10Int(n - 1);
}

inline int32_t castFraction(int32_t frac, int32_t scale)
{
  return scale <= PYTHON_DATETIME_TIME_MICROSEC_BITS
             ? frac
             : frac / powTenSB4[scale - PYTHON_DATETIME_TIME_MICROSEC_BITS];
}

int32_t getNumberOfDigit(int32_t num);

// TODO : I think we can just keep int64_t version, since we can call the
// function with implicit conversion from int32 to int64
int32_t getHourFromSeconds(int64_t seconds, int32_t scale);

int32_t getMinuteFromSeconds(int64_t seconds, int32_t scale);

int32_t getSecondFromSeconds(int64_t seconds, int32_t scale);

int32_t getMicrosecondFromSeconds(int64_t seconds, int32_t scale);

int32_t getHourFromSeconds(int32_t seconds, int32_t scale);

int32_t getMinuteFromSeconds(int32_t seconds, int32_t scale);

int32_t getSecondFromSeconds(int32_t seconds, int32_t scale);

int32_t getMicrosecondFromSeconds(int32_t seconds, int32_t scale);

double secondsToDouble(int64_t seconds, int32_t scale);

inline double secondsFractionToDouble(int64_t seconds, int32_t frac,
                                      int32_t scale)
{
  return static_cast<double>(seconds) +
         static_cast<double>(castFraction(frac, scale)) /
             powTenSB4[std::min(scale, PYTHON_DATETIME_TIME_MICROSEC_BITS)];
}

// TODO
double bigSecondToDouble();

}  // namespace internal
}  // namespace sf

#endif  // PC_UTIL_TIME_HPP
