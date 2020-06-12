#!/bin/bash -e
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/set_base_image.sh
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

mkdir -p $CONNECTOR_DIR/dist
cd $THIS_DIR/docker/connector_build

CONTAINER_NAME=build_connector

echo "[Info] Start building docker image"
docker build -t manylinux:1.0 --build-arg BASE_IMAGE=$BASE_IMAGE_MANYLINUX1 -f Dockerfile .

user_id=$(id -u $USER)
docker run \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    --mount type=bind,source="$CONNECTOR_DIR",target=/home/user/snowflake-connector-python \
    manylinux:1.0 \
    /home/user/snowflake-connector-python/ci/build_pyarrow_linux.sh $1
