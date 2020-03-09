#!/bin/bash -e
#
# Install Snowflake Python Connector
#
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $THIS_DIR/..
PYTHON_VERSION=$1
source "/home/user/venv-build-${PYTHON_VERSION}/bin/activate"
rm -rf build/
export ENABLE_EXT_MODULES=true
rm -f generated_version.py
python setup.py bdist_wheel -d $THIS_DIR/../dist/docker/$PYTHON_VERSION/
unset ENABLE_EXT_MODULES

mkdir -p $THIS_DIR/../dist/docker/repaired_wheels
auditwheel repair --plat manylinux2010_x86_64 -L connector $THIS_DIR/../dist/docker/$PYTHON_VERSION/*.whl -w $THIS_DIR/../dist/docker/repaired_wheels
rm $THIS_DIR/../dist/docker/repaired_wheels/*manylinux1_x86_64.whl || true
