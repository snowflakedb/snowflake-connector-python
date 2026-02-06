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
    export BASE_IMAGE_MANYLINUX2014=$INTERNAL_REPO/manylinux2014_x86_64:2025.02.12-1
    export BASE_IMAGE_MANYLINUX2014AARCH64=$INTERNAL_REPO/manylinux2014_aarch64:2025.02.12-1
    export BASE_IMAGE_ROCKYLINUX9=$INTERNAL_REPO/rockylinux:9
else
    echo "[INFO] Pull docker images from public registry"
    export BASE_IMAGE_MANYLINUX2014=quay.io/pypa/manylinux2014_x86_64
    export BASE_IMAGE_MANYLINUX2014AARCH64=quay.io/pypa/manylinux2014_aarch64
    export BASE_IMAGE_ROCKYLINUX9=rockylinux:9
fi
