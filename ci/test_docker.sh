#!/bin/bash -e
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/set_base_image.sh
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
# In case this is not run locally and not on Jenkins
WORKSPACE=${WORKSPACE:-$HOME}

cd $THIS_DIR/docker/connector_test

echo "[Info] Start building docker image"
docker build -t test_connector:1.0 --build-arg BASE_IMAGE=$BASE_IMAGE_MANYLINUX2010 -f Dockerfile .

user_id=$(id -u $USER)
docker run -it --network=host \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    -e PYTHON_ENV \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e SF_REGRESS_LOGS \
    -e SF_PROJECT_ROOT \
    -e WORKSPACE \
    --mount type=bind,source="$WORKSPACE",target="$WORKSPACE" \
    test_connector:1.0 \
    ${THIS_DIR}/test.sh $1
