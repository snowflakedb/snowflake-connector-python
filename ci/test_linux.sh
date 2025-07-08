#!/bin/bash -e
#
# Test Snowflake Connector in Linux
# NOTES:
#   - Versions to be tested should be passed in as the first argument, e.g: "3.9 3.10". If omitted 3.9-3.13 will be assumed.
#   - This script assumes that ../dist/repaired_wheels has the wheel(s) built for all versions to be tested
#   - This is the script that test_docker.sh runs inside of the docker container

PYTHON_VERSIONS="${1:-3.9 3.10 3.11 3.12 3.13}"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

# Install one copy of tox
python3.10 -m pip install -U tox>=4

source ${THIS_DIR}/log_analyze_setup.sh

if [[ -d ${CLIENT_LOG_DIR_PATH_DOCKER} ]]; then
    rm -rf ${CLIENT_LOG_DIR_PATH_DOCKER}/*
else
    mkdir ${CLIENT_LOG_DIR_PATH_DOCKER}
fi

# replace test password with a more complex one, and generate known ssm file
python3.10 -m pip install -U snowflake-connector-python --only-binary=cffi >& /dev/null
python3.10 ${THIS_DIR}/change_snowflake_test_pwd.py
mv ${CONNECTOR_DIR}/test/parameters_jenkins.py ${CONNECTOR_DIR}/test/parameters.py

# Fetch wiremock
curl https://repo1.maven.org/maven2/org/wiremock/wiremock-standalone/3.11.0/wiremock-standalone-3.11.0.jar --output ${CONNECTOR_DIR}/.wiremock/wiremock-standalone.jar

# Run tests
cd $CONNECTOR_DIR
if [[ "$is_old_driver" == "true" ]]; then
    # Old Driver Test
    echo "[Info] Running old connector tests"
    python3.10 -m tox -e olddriver
else
    for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
        echo "[Info] Testing with ${PYTHON_VERSION}"
        SHORT_VERSION=$(python3.10 -c "print('${PYTHON_VERSION}'.replace('.', ''))")
        CONNECTOR_WHL=$(ls $CONNECTOR_DIR/dist/snowflake_connector_python*cp${SHORT_VERSION}*manylinux2014*.whl | sort -r | head -n 1)
        TEST_LIST=`echo py${PYTHON_VERSION/\./}-{unit-parallel,integ-parallel,pandas-parallel,sso}-ci | sed 's/ /,/g'`
        TEST_ENVLIST=fix_lint,$TEST_LIST,py${PYTHON_VERSION/\./}-coverage
        echo "[Info] Running tox for ${TEST_ENVLIST}"

        python3.10 -m tox run -e ${TEST_ENVLIST} --installpkg ${CONNECTOR_WHL}
    done
fi
