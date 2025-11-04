#!/bin/bash

export SNOWFLAKE_CONNECTOR_PYTHON_DIR=/repo/snowflake-connector-python
export CONDA_BLD_PATH=/repo/conda-bld

mkdir -p $CONDA_BLD_PATH
cd "$SNOWFLAKE_CONNECTOR_PYTHON_DIR"
# Build with .tar.bz2 (pkg_format = 1) and .conda (pkg_format = 2).
conda config --set conda_build.pkg_format 1
bash ./ci/anaconda/conda_build.sh
conda config --set conda_build.pkg_format 2
bash ./ci/anaconda/conda_build.sh
conda config --remove-key conda_build.pkg_format
conda build purge
cd $CONDA_BLD_PATH
conda index .
chmod -R o+w,g+w $CONDA_BLD_PATH
