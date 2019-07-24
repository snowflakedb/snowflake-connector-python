# Copyright (c) 2018-2019 Snowflake Computing, Inc. All rights reserved.
#
# CMakeList for PythonConnector Extension
#
cmake_minimum_required(VERSION 2.8)
project(PythonConnectorExtension)
set(CMAKE_VERBOSE_MAKEFILE ON)

include("PathUtil.cmake")

if (NOT DEFINED PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Python executable is not specified. Please provide with -DPYTHON_EXECUTABLE")
else()
    message("Python executable provided is " ${PYTHON_EXECUTABLE})
endif()

if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

if (LINUX)
    set(PLATFORM linux)
    message("Platform: Linux")
endif ()
if (APPLE)
    set(PLATFORM darwin)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "Minimum OS X deployment version")
    message("Platform: Apple OSX")
endif ()
if ("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set(PLATFORM win64)
    message("Platform: Windows 64bit")
endif ()
if ("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set(PLATFORM win32)
    message("Platform: Windows 32bit")
endif ()


get_python_include_dir(PYTHON_INCLUDE_DIR)
get_pyarrow_include_dir(PYARROW_INCLUDE_DIR)

if (UNIX)
    get_pyarrow_unix_link(PYARROW_UNIX_LINK)
endif()

SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++11")

include_directories(${PYARROW_INCLUDE_DIR})
include_directories(${PYTHON_INCLUDE_DIR})

set(SOURCE_FILES_ARROW_ITERATOR
        ArrowIterator/PyArrowChunkIteratorDef.cpp
        ArrowIterator/CArrowChunkIterator.cpp
        ArrowIterator/CArrowChunkIterator.hpp
        ArrowIterator/IColumnConverter.hpp
        ArrowIterator/IntConverter.cpp
        ArrowIterator/IntConverter.hpp
        ArrowIterator/StringConverter.cpp
        ArrowIterator/StringConverter.hpp
        )

if (UNIX)
    set(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} ${PYARROW_UNIX_LINK})
endif()


add_library("arrow_iterator" SHARED ${SOURCE_FILES_ARROW_ITERATOR})
