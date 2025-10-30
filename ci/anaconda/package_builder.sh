#!/bin/bash

export SNOWFLAKE_CONNECTOR_PYTHON_DIR=/repo/snowflake-connector-python
export CONDA_BLD_PATH=/repo/conda-bld

mkdir -p $CONDA_BLD_PATH
cd "$SNOWFLAKE_CONNECTOR_PYTHON_DIR"
conda config --set conda_build.pkg_format 1
bash ./ci/anaconda/conda_build.sh
# NOTE: the below is to output the build in .conda format.
# To do so, we set conda_build.pkg_format = 2 and then
# remove it later to go back to default behavior.
conda config --set conda_build.pkg_format 2
bash ./ci/anaconda/conda_build.sh
conda config --remove-key conda_build.pkg_format
conda build purge
cd $CONDA_BLD_PATH
conda index .
chmod -R o+w,g+w $CONDA_BLD_PATH
