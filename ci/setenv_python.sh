#!/bin/bash -ex
#
# Set environment varible for Python
#
set -o pipefail
if [[ -z "$DONE_SETENV_PYTHON" ]]; then
    export DONE_SETENV_PYTHON=1
    PYTHON_BASE_DIR=${WORKSPACE:-$HOME/sf/deployments/connectors}

    # Python version.
    python_version=${python_version:-3.6.8}

    # Compilers used to build Python executable
    python_exe_base=python-dist-gcc-g++

    python_exe_name=${python_exe_base}-${python_version}

    # set environment variables for Python
    PYTHON_HOME=$PYTHON_BASE_DIR/${python_exe_name}
    export PATH=$PYTHON_HOME/bin:$PATH
    export LD_LIBRARY_PATH=$PYTHON_HOME/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    export LDFLAGS="-L$PYTHON_HOME/lib"
fi
