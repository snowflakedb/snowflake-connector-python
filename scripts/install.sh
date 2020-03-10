#!/bin/bash -e
#
# Install Snowflake Python Connector
#
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    curl -O https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-macosx10.9.pkg
    sudo installer -pkg python-${PYTHON_VERSION}-macosx10.9.pkg -target /
    which python3
    python3 --version
    python3 -m venv venv
else
    sudo apt-get update
    pip install -U virtualenv
    python -m virtualenv venv
fi
if [[ -n "$SNOWFLAKE_AZURE" ]]; then
    openssl aes-256-cbc -k "$super_azure_secret_password" -in parameters_az.py.enc -out test/parameters.py -d
elif [[ -n "$SNOWFLAKE_GCP" ]]; then
    openssl aes-256-cbc -k "$super_gcp_secret_password" -in parameters_gcp.py.enc -out test/parameters.py -d
else
    openssl aes-256-cbc -k "$super_secret_password" -in parameters.py.enc -out test/parameters.py -d
fi

source ./venv/bin/activate

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    export ENABLE_EXT_MODULES=true
    cd $THIS_DIR/..
    pip install Cython pyarrow==0.16.0 wheel
    python setup.py bdist_wheel
    unset ENABLE_EXT_MODULES
    CONNECTOR_WHL=$(ls $THIS_DIR/../dist/snowflake_connector_python*.whl | sort -r | head -n 1)
    pip install -U ${CONNECTOR_WHL}[pandas,development]
else
    pv=${TRAVIS_PYTHON_VERSION/./}
    $THIS_DIR/build_docker.sh $pv
    CONNECTOR_WHL=$(ls $THIS_DIR/../dist/docker/repaired_wheels/snowflake_connector_python*cp${PYTHON_ENV}*.whl | sort -r | head -n 1)
    pip install -U ${CONNECTOR_WHL}[pandas,development]
    cd $THIS_DIR/..
fi
pip list --format=columns
