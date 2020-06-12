#!/bin/bash -e
#
# Install Snowflake Python Connector
#
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $THIS_DIR/set_base_image.sh

cd $THIS_DIR/docker/connector_build

echo "[Info] Start building dokcer image"
docker build -t manylinux:1.0 --build-arg BASE_IMAGE=$BASE_IMAGE_MANYLINUX1 -f Dockerfile .

user_id=$(id -u $USER)
docker run -e LOCAL_USER_ID=$user_id --mount type=bind,source="$THIS_DIR/..",target=/home/user/connector manylinux:1.0 \
    /home/user/connector/ci/build_linux.sh $1
