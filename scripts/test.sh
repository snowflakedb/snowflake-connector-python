#!/bin/bash -e
#
# Test Snowflake Connector
# Note this is the script that test_docker.sh runs inside of the docker container
#
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# shellcheck disable=SC1090
source "${THIS_DIR}/py_exec.sh"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
CONNECTOR_WHL=$(ls $CONNECTOR_DIR/dist/docker/repaired_wheels/snowflake_connector_python*cp${PYTHON_ENV}*manylinux2010*.whl | sort -r | head -n 1)
TEST_ENVLIST=fix_lint,py${PYTHON_ENV}-ci,py${PYTHON_ENV}-pandas-ci,py${PYTHON_ENV}-sso-ci,coverage

if [[ -n "$PIP_INDEX_URL" ]]; then
  echo "PIP_INDEX_URL before now: ${PIP_INDEX_URL}"
  unset PIP_INDEX_URL
fi

# setup venv with tox and run tests with tox
${PYTHON_EXEC} -m venv tox_env
source tox_env/bin/activate
python -m pip install -U tox tox-external-wheels>=0.1.4
cd $CONNECTOR_DIR

tox -e ${TEST_ENVLIST} --external_wheels ${CONNECTOR_WHL}

deactivate
