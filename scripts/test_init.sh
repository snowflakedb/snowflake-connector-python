#!/bin/bash -e
#
# Initialize test
#
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
source $THIS_DIR/build_init.sh


function resetup_test_env() {
  resetup_env "$TEST_VIRTUALENV"
}

function setup_test_env() {
  setup_env "$TEST_VIRTUALENV"
}

function install_test_packages() {
    #
    # Install Test Packages
    #
    local target="connector"
    local package_name=$1
    local virtualenv=$2

    [[ -z "$package_name" ]] && package_name=$target
    [[ -z "$virtualenv" ]] && virtualenv=python3.5
    connector_whl=$(ls $CONNECTOR_DIR/dist/snowflake_connector_python*${python_svn_revision}*.whl | sort -r | head -n 1)
    target_whl=$(ls $CONNECTOR_DIR/dist/snowflake_${package_name}*${python_svn_revision}*.whl | sort -r | head -n 1)

    log INFO "Installing ${target} for tests"
    resetup_test_env

    source $TEST_VIRTUALENV/bin/activate
    run_cmd "pip install -U pip setuptools" "test_$target.log"
    run_cmd "pip install -U ${target_whl}" "test_$target.log"
    run_cmd "pip install -U ${connector_whl}[development]" "test_$target.log" # ensure the latest Python Connector. Don't put together with CLI install
    deactivate
}

function run_tests() {
    #
    # Run Tests
    #

    local target="connector"
    local target_tests=$2

    log INFO "Running Tests: $target"
    cd $CONNECTOR_DIR
    find ./test -name "__pycache__" -exec rm -rf {} \; 1>/dev/null || true
    find ./test -name "*.pyc" -exec rm -rf {} \; 1>/dev/null || true
    TEST_VIRTUALENV=$VIRTUAL_ENV_DIR/${target}_tests
    source $TEST_VIRTUALENV/bin/activate
    run_cmd "coverage erase" "test_${target}.log"
    run_cmd "py.test -vvv $target_tests --junitxml=$SF_REGRESS_LOGS/junit-$target-tests.xml" "test_${target}.log" "do_tee"
    deactivate
}
