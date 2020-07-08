#!/bin/bash -e
#
# Test Snowflake Connector on a Darwin Jenkins slave
# NOTES:
#   - Versions to be tested should be passed in as the first argument, e.g: "3.5 3.6". If omitted 3.5-3.8 will be assumed.
#   - This script uses .. to download the newest wheel files from S3

PYTHON_VERSIONS="${1:-3.5 3.6 3.7 3.8}"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

cd ${CONNECTOR_DIR}
cat << PARAM > ${CONNECTOR_DIR}/test/parameters.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
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

echo "[Info] Downloading wheel files from s3"
aws s3 cp --only-show-errors \
    s3://sfc-jenkins/repository/python_connector/mac64/$branch/$base_svn_revision/ . \
    --exclude "*" \
    --include "*.whl" --recursive

export JUNIT_REPORT_DIR=${SF_REGRESS_LOGS:-$CONNECTOR_DIR}
export COV_REPORT_DIR=${CONNECTOR_DIR}

cd $CONNECTOR_DIR

for PYTHON_VERSION in ${PYTHON_VERSIONS}; do
    echo "[Info] Testing with ${PYTHON_VERSION}"
    SHORT_VERSION=$(python3 -c "print('${PYTHON_VERSION}'.replace('.', ''))")
    CONNECTOR_WHL=$(ls ${CONNECTOR_DIR}/snowflake_connector_python*cp${SHORT_VERSION}*.whl)
    TEST_ENVLIST=fix_lint,py${SHORT_VERSION}{,-pandas,-sso}-ci,coverage
    echo "[Info] Running tox for ${TEST_ENVLIST}"

    # https://github.com/tox-dev/tox/issues/1485
    # tox seems to not work inside virtualenv, so manually installed tox and trigger system default tox
    /Library/Frameworks/Python.framework/Versions/3.5/bin/tox -e ${TEST_ENVLIST} --external_wheels ${CONNECTOR_WHL}
done
