#!/bin/bash -e
#
# Use the internal docker registry if running on Jenkins
#
set -o pipefail
INTERNAL_REPO=artifactory.ci1.us-west-2.aws-dev.app.snowflake.com/internal-production-docker-snowflake-virtual
if [[ -n "$NEXUS_PASSWORD" ]]; then
    echo "[INFO] Pull docker images from $INTERNAL_REPO"
    NEXUS_USER=${USERNAME:-jenkins}
    docker login --username "$NEXUS_USER" --password "$NEXUS_PASSWORD" $INTERNAL_REPO
    export BASE_IMAGE_MANYLINUX2014=$INTERNAL_REPO/manylinux2014_x86_64:2025.02.12-1
    export BASE_IMAGE_MANYLINUX2014AARCH64=$INTERNAL_REPO/manylinux2014_aarch64:2025.02.12-1
    export BASE_IMAGE_ROCKYLINUX9=$INTERNAL_REPO/rockylinux:9
else
    echo "[INFO] Pull docker images from public registry"
    export BASE_IMAGE_MANYLINUX2014=quay.io/pypa/manylinux2014_x86_64
    export BASE_IMAGE_MANYLINUX2014AARCH64=quay.io/pypa/manylinux2014_aarch64
    export BASE_IMAGE_ROCKYLINUX9=rockylinux:9
fi
