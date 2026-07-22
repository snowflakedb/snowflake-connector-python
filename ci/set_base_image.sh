#!/bin/bash -e
#
# Use the internal docker registry if running on Jenkins
# Artifactory virtual repos support anonymous access; authentication
# is handled via "sf artifact oci auth" in the Jenkinsfile.
#
set -o pipefail
INTERNAL_REPO=artifactory.ci1.us-west-2.aws-dev.app.snowflake.com/internal-production-docker-snowflake-virtual
if [[ -n "$JENKINS_HOME" ]]; then
    echo "[INFO] Pull docker images from $INTERNAL_REPO"
    export BASE_IMAGE_MANYLINUX2014=$INTERNAL_REPO/docker/manylinux2014_x86_64:latest
    export BASE_IMAGE_MANYLINUX2014AARCH64=$INTERNAL_REPO/docker/manylinux2014_aarch64:latest
    # manylinux_2_28 via Artifactory — available once IT mirrors quay.io/pypa/manylinux_2_28_*
    export BASE_IMAGE_MANYLINUX2_28=$INTERNAL_REPO/docker/manylinux_2_28_x86_64:latest
    export BASE_IMAGE_MANYLINUX2_28AARCH64=$INTERNAL_REPO/docker/manylinux_2_28_aarch64:latest
    export BASE_IMAGE_ROCKYLINUX9=$INTERNAL_REPO/docker/rockylinux:9
else
    echo "[INFO] Pull docker images from public registry"
    export BASE_IMAGE_MANYLINUX2014=quay.io/pypa/manylinux2014_x86_64
    export BASE_IMAGE_MANYLINUX2014AARCH64=quay.io/pypa/manylinux2014_aarch64
    export BASE_IMAGE_MANYLINUX2_28=quay.io/pypa/manylinux_2_28_x86_64
    export BASE_IMAGE_MANYLINUX2_28AARCH64=quay.io/pypa/manylinux_2_28_aarch64
    export BASE_IMAGE_ROCKYLINUX9=rockylinux:9
fi

# Public manylinux_2_28 images — used for cp314t builds unconditionally.
# quay.io/pypa is reachable from Jenkins Linux agents without Artifactory,
# so these bypass the Artifactory mirror dependency for free-threaded wheels.
export BASE_IMAGE_MANYLINUX2_28_PUBLIC=quay.io/pypa/manylinux_2_28_x86_64
export BASE_IMAGE_MANYLINUX2_28_PUBLIC_AARCH64=quay.io/pypa/manylinux_2_28_aarch64
