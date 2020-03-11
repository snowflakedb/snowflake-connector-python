#!/bin/bash -e
#
# Test Snowflake Connector
# NOTE: this job uses WORKSPACE to download the newest wheel file, this is set by build_init if not set on outside
#
export TERM=vt100
export PATH=/usr/local/bin:$PATH

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
source $THIS_DIR/py_exec.sh
source $THIS_DIR/test_init.sh

sf_password=${sf_password:-test}

cd $WORKSPACE
cat << PARAM > $CONNECTOR_DIR/test/parameters.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

#
# DON'T PUBLISH THIS CODE. THIS IS INTERNAL USE ONLY.
#

CONNECTION_PARAMETERS = {
    'account': '$sf_account',
    'user': '$sf_user',
    'password': '$sf_password',
    'schema': '$sf_schema',
    'database': '$sf_database',
    'protocol': 'https',
    'host': '${sf_account}.snowflakecomputing.com',
    'port': '443',
    'warehouse': '${sf_warehouse}',
}

PARAM

log INFO "Downloading wheel file from s3"
aws s3 cp --only-show-errors \
    s3://sfc-jenkins/repository/python_connector/mac64/$branch/$base_svn_revision/ . \
    --exclude "*" \
    --include "*.whl" --recursive

log INFO "Testing Connector in python${PYTHON_ENV}"

CONNECTOR_WHL=$(ls ${WORKSPACE}/snowflake_connector_python*cp${PYTHON_ENV}*.whl)
TEST_ENVLIST=fix_lint,py${PYTHON_ENV}-ci,py${PYTHON_ENV}-pandas-ci,coverage

cd $CONNECTOR_DIR

export JUNIT_REPORT_DIR=$SF_REGRESS_LOGS
export COV_REPORT_DIR=$WORKSPACE
# https://github.com/tox-dev/tox/issues/1485
# tox seems does not work inside virtualenv, so manually installed tox and trigger system default tox
/Library/Frameworks/Python.framework/Versions/3.5/bin/tox -e ${TEST_ENVLIST} --external_wheels ${CONNECTOR_WHL}
