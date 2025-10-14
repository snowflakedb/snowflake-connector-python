#!/bin/bash -e
# Test Snowflake Python Connector in Rocky Linux 9 Docker
# NOTES:
#   - By default this script runs Python 3.9 tests, as these are installed in dev vms
#   - To compile only a specific version(s) pass in versions like: `./test_rockylinux9_docker.sh "3.9 3.11"`

set -o pipefail

# In case this is ran from dev-vm
PYTHON_ENV=${1:-3.9}

# Set constants
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
WORKSPACE=${WORKSPACE:-${CONNECTOR_DIR}}
source $THIS_DIR/set_base_image.sh

cd $THIS_DIR/docker/connector_test_rockylinux9

CONTAINER_NAME=test_pyconnector_rockylinux9

echo "[Info] Building docker image for Rocky Linux 9"
BASE_IMAGE=${BASE_IMAGE_ROCKYLINUX9:-rockylinux:9}
GOSU_URL=https://github.com/tianon/gosu/releases/download/1.14/gosu-amd64

docker build --pull -t ${CONTAINER_NAME}:1.0 --build-arg BASE_IMAGE=$BASE_IMAGE --build-arg GOSU_URL="$GOSU_URL" . -f Dockerfile

user_id=$(id -u ${USER})
docker run --network=host \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=${user_id} \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e SF_REGRESS_LOGS \
    -e SF_PROJECT_ROOT \
    -e cloud_provider \
    -e JENKINS_HOME \
    -e is_old_driver \
    -e GITHUB_ACTIONS \
    -e USE_PASSWORD=true \
    --mount type=bind,source="${CONNECTOR_DIR}",target=/home/user/snowflake-connector-python \
    ${CONTAINER_NAME}:1.0 \
    /home/user/snowflake-connector-python/ci/test_rockylinux9.sh ${PYTHON_ENV}

