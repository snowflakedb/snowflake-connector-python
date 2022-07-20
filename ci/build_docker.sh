#!/bin/bash -e
#
# Build Snowflake Python Connector in Docker
# NOTES:
#   - To compile only a specific version(s) pass in versions like: `./build_docker.sh "3.7 3.8"`
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/set_base_image.sh
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"

mkdir -p $CONNECTOR_DIR/dist
cd $THIS_DIR/docker/connector_build

CONTAINER_NAME=build_pyconnector
arch=$(uname -p)

echo "[Info] Building docker image"
if [[ "$arch" == "aarch64" ]]; then
  BASE_IMAGE=$BASE_IMAGE_MANYLINUX2014AARCH64
  GOSU_URL=https://github.com/tianon/gosu/releases/download/1.11/gosu-arm64
else
  BASE_IMAGE=$BASE_IMAGE_MANYLINUX2014
  GOSU_URL=https://github.com/tianon/gosu/releases/download/1.11/gosu-amd64
fi

docker build --pull -t ${CONTAINER_NAME}:1.0 --build-arg BASE_IMAGE=$BASE_IMAGE --build-arg GOSU_URL="$GOSU_URL" . -f Dockerfile

echo "[Info] Building Python Connector"
user_id=$(id -u ${USER})
docker run \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=${user_id} \
    --mount type=bind,source="${CONNECTOR_DIR}",target=/home/user/snowflake-connector-python \
    ${CONTAINER_NAME}:1.0 \
    /home/user/snowflake-connector-python/ci/build_linux.sh $1
