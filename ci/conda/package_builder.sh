#!/bin/bash
#
# Script to execute all of the conda aarch64 recipe building for Stored Proc
# Runs in a C8 docker container with miniconda installed
# IMAGE_NAME: stored_proc_anaconda_aarch64
#
#  Author: John Lin
#

# Paths inside of docker container - mount Stored-Proc-Python-Connector
export SF_PROJECT_ROOT=/repo
export SNOWFLAKE_CONNECTOR_PYTHON_DIR=/repo/snowflake-connector-python
export CONDA_BLD_PATH=/repo/conda-bld

# Run command needs to passs in $build_name
export PKG_NAME=${build_name}-linux-aarch64.tar.gz
mkdir -p $CONDA_BLD_PATH
cd "$SNOWFLAKE_CONNECTOR_PYTHON_DIR"
conda config --set conda_build.pkg_format 1
bash ./ci/conda/conda_build.sh
# NOTE: the below is to output the build in .conda format.
# To do so, we set conda_build.pkg_format = 2 and then
# remove it later to go back to default behavior.
conda config --set conda_build.pkg_format 2
bash ./ci/conda/conda_build.sh
conda config --remove-key conda_build.pkg_format
conda build purge
cd $CONDA_BLD_PATH
conda index .
#tar -czvf $PKG_NAME linux-aarch64
