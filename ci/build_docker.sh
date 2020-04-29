#!/bin/bash -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

mkdir -p $CONNECTOR_DIR/dist
cd $CONNECTOR_DIR/docker/manylinux2010

CONTAINER_NAME=build_connector

echo "[Info] Start building docker image"
docker build -t manylinux:1.0 -f Dockerfile-x86_64_base .

user_id=$(id -u $USER)
docker run \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    --mount type=bind,source="$CONNECTOR_DIR",target=/home/user/snowflake-connector-python \
    manylinux:1.0 \
    /home/user/snowflake-connector-python/ci/build_pyarrow_linux.sh $1
