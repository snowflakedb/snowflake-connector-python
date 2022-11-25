#!/bin/bash -e
#
# Test Snowflake Connector in Linux
# NOTES:
#   - Versions to be tested should be passed in as the first argument, e.g: "3.7 3.8". If omitted 3.7-3.11 will be assumed.
#   - This script assumes that ../dist/repaired_wheels has the wheel(s) built for all versions to be tested
#   - This is the script that test_docker.sh runs inside of the docker container

PYTHON_VERSIONS="${1:-3.7 3.8 3.9 3.10 3.11}"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

# Install one copy of tox
python3 -m pip install -U tox tox-external-wheels

source ${THIS_DIR}/log_analyze_setup.sh

if [[ -d ${CLIENT_LOG_DIR_PATH_DOCKER} ]]; then
    rm -rf ${CLIENT_LOG_DIR_PATH_DOCKER}/*
else
    mkdir ${CLIENT_LOG_DIR_PATH_DOCKER}
fi

# replace test password with a more complex one, and generate known ssm file
python3 -m pip install -U snowflake-connector-python --only-binary=cffi >& /dev/null
python3 ${THIS_DIR}/change_snowflake_test_pwd.py
mv ${CONNECTOR_DIR}/test/parameters_jenkins.py ${CONNECTOR_DIR}/test/parameters.py

# Run tests
cd $CONNECTOR_DIR
if [[ "$is_old_driver" == "true" ]]; then
    # Old Driver Test
    echo "[Info] Running old connector tests"
    python3 -m tox -e olddriver
else
    for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
        echo "[Info] Testing with ${PYTHON_VERSION}"
        SHORT_VERSION=$(python3 -c "print('${PYTHON_VERSION}'.replace('.', ''))")
        CONNECTOR_WHL=$(ls $CONNECTOR_DIR/dist/snowflake_connector_python*cp${SHORT_VERSION}*manylinux2014*.whl | sort -r | head -n 1)
        TEST_ENVLIST=fix_lint,py${SHORT_VERSION}-{unit,integ,pandas,sso}-ci,py${SHORT_VERSION}-coverage
        echo "[Info] Running tox for ${TEST_ENVLIST}"

        python3 -m tox -e ${TEST_ENVLIST} --external_wheels ${CONNECTOR_WHL}
    done
fi
