#!/bin/bash -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
# In case this is not run locally and not on Jenkins
WORKSPACE=${WORKSPACE:-$HOME}

cd $CONNECTOR_DIR/docker/python_connector_tests

echo "[Info] Start building docker image"
docker build -t test_connector:1.0 -f Dockerfile-x86_64_base .

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
