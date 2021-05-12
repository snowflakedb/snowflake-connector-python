#!/bin/bash -e
#
# Use the internal docker registry if running on Jenkins
#
set -o pipefail
INTERNAL_REPO=nexus.int.snowflakecomputing.com:8086
if [[ -n "$NEXUS_PASSWORD" ]]; then
    echo "[INFO] Pull docker images from $INTERNAL_REPO"
    NEXUS_USER=${USERNAME:-jenkins}
    docker login --username "$NEXUS_USER" --password "$NEXUS_PASSWORD" $INTERNAL_REPO
    export BASE_IMAGE_MANYLINUX2010=nexus.int.snowflakecomputing.com:8086/docker/manylinux2010_x86_64
    export BASE_IMAGE_MANYLINUX2014=nexus.int.snowflakecomputing.com:8086/docker/manylinux2014_x86_64
    export BASE_IMAGE_MANYLINUX2014AARCH64=nexus.int.snowflakecomputing.com:8086/docker/manylinux2014_aarch64
else
    echo "[INFO] Pull docker images from public registry"
    export BASE_IMAGE_MANYLINUX2010=quay.io/pypa/manylinux2010_x86_64
    export BASE_IMAGE_MANYLINUX2014=quay.io/pypa/manylinux2014_x86_64
    export BASE_IMAGE_MANYLINUX2014=quay.io/pypa/manylinux2014_aarch64
fi
