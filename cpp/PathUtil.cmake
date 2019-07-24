cmake_minimum_required(VERSION 2.8)
project(PythonConnectorExtension)
set(CMAKE_VERBOSE_MAKEFILE ON)

function(get_pyarrow_include_dir PYARROW_INCLUDE_DIR)
    exec_program(${PYTHON_EXECUTABLE}
            ARGS "-c \"import pyarrow; print(pyarrow.get_include())\""
            OUTPUT_VARIABLE RESULT
            RETURN_VALUE PYARROW_NOT_FOUND
            )
    if(PYARROW_NOT_FOUND)
        message(FATAL_ERROR "pyarrow headers not found")
    else()
        message("Pyarrow header is located at " ${RESULT})
        set(${PYARROW_INCLUDE_DIR} ${RESULT} PARENT_SCOPE)
    endif()
endfunction()

function(get_python_include_dir PYTHON_INCLUDE_DIR)
    exec_program(${PYTHON_EXECUTABLE}
            ARGS "-c \"from sysconfig import get_paths as gp; print(gp()['include'])\""
            OUTPUT_VARIABLE RESULT
            RETURN_VALUE PYTHON_NOT_FOUND
            )
    if(PYTHON_NOT_FOUND)
        message(FATAL_ERROR "python headers not found")
    else()
        message("Python header is located at " ${RESULT})
        set(${PYTHON_INCLUDE_DIR} ${RESULT} PARENT_SCOPE)
    endif()
endfunction()

function (get_pyarrow_unix_link PYARROW_UNIX_LINK)
    exec_program(${PYTHON_EXECUTABLE}
            ARGS "-c \"import pyarrow;import glob;lib_dir=pyarrow.get_library_dirs();lib=pyarrow.get_libraries();print(' '.join((glob.glob(lib_dir[0] + '/lib' + l + '.so*'))[0] for l in lib))\""
            OUTPUT_VARIABLE RESULT
            RETURN_VALUE RETURNCODE
            )

    set(${PYARROW_UNIX_LINK} ${RESULT} PARENT_SCOPE)
endfunction()
