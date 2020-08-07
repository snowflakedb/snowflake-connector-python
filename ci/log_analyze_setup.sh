#!/bin/bash -e
#
# preparation for log analyze
#

# DOCKER ROOT /home/user/snowflake-connector-python

export CLIENT_LOG_DIR_PATH_DOCKER=/home/user/snowflake-connector-python/ssm_rt_log
export CLIENT_LOG_DIR_PATH=$WORKSPACE/target/ssm_rt_log
echo "[INFO] CLIENT_LOG_DIR_PATH=$CLIENT_LOG_DIR_PATH"
echo "[INFO] CLIENT_LOG_DIR_PATH_DOCKER=$CLIENT_LOG_DIR_PATH_DOCKER"

export CLIENT_KNOWN_SSM_FILE_PATH_DOCKER=$CLIENT_LOG_DIR_PATH_DOCKER/rt_jenkins_log_known_ssm.txt
export CLIENT_KNOWN_SSM_FILE_PATH=$CLIENT_LOG_DIR_PATH/rt_jenkins_log_known_ssm.txt
echo "[INFO] CLIENT_KNOWN_SSM_FILE_PATH=$CLIENT_KNOWN_SSM_FILE_PATH"
echo "[INFO] CLIENT_KNOWN_SSM_FILE_PATH_DOCKER=$CLIENT_KNOWN_SSM_FILE_PATH_DOCKER"

# [required envs]
# To close log analyze, just set ENABLE_CLIENT_LOG_ANALYZE to not "true", e.g. "false".
export ENABLE_CLIENT_LOG_ANALYZE="true"
# export ENABLE_CLIENT_LOG_ANALYZE="false"

# The environment variable used by log analyze module
export CLIENT_DRIVER_NAME=PYTHON
