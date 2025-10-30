
# Before manual running, do something similar to the following in command line.
# export WORKSPACE=/home/jdoe/my_workspace;
# export build_number=321;
# export aarch64_base_image=<location_of_centos8_aarch64_base_image>;
# export x86_base_image=<location_of_centos8_x86_base_image>;

# Here miniconda-install.sh is just a installer that I downloaded from Anaconda official site,
# https://repo.anaconda.com/miniconda/


if [[ -z $WORKSPACE ]]; then
  # Development on dev machine
  WORKSPACE=$HOME
fi

# ===== Build docker image =====
cd $WORKSPACE

docker build \
  --build-arg ARCH=$(uname -m) \
  --build-arg AARCH64_BASE_IMAGE="${aarch64_base_image}" \
  --build-arg X86_BASE_IMAGE="${x86_base_image}" \
  -t snowflake_connector_python_image \
  -f - . <<'DOCKERFILE'
# Use different base images based on target platform

ARG ARCH
ARG AARCH64_BASE_IMAGE=artifactory.int.snowflakecomputing.com/development-docker-virtual/arm64v8/centos:8
ARG X86_BASE_IMAGE=artifactory.int.snowflakecomputing.com/development-docker-virtual/centos:8

FROM ${AARCH64_BASE_IMAGE} AS base-aarch64

FROM ${X86_BASE_IMAGE} AS base-x86_64



# Select the appropriate base image based on target architecture

FROM base-${ARCH} AS base

COPY miniconda-install.sh .



RUN chmod 0755 miniconda-install.sh



RUN mkdir -p /etc/miniconda && bash miniconda-install.sh -b -u -p /etc/miniconda/



RUN ln -s /etc/miniconda/bin/conda /usr/bin/conda && rm miniconda-install.sh
DOCKERFILE

# Go back to the original directory
cd $WORKSPACE


# Check to make sure repos exist to build conda packages
if [[ -d $WORKSPACE/snowflake-connector-python ]]; then
  echo "Check snowflake-connector-python repo exists - PASSED"
else
  echo "[FAILURE] Please clone snowflake-connector-python repo at $WORKSPACE/snowflake-connector-python"
fi

# Run packager in docker image
docker run \
  -v $WORKSPACE/snowflake-connector-python/:/repo/snowflake-connector-python \
  -v $WORKSPACE/conda-bld:/repo/conda-bld \
  -e SNOWFLAKE_CONNECTOR_PYTHON_BUILD_NUMBER=${build_number} \
  snowflake_connector_python_image \
  /repo/snowflake-connector-python/ci/anaconda/package_builder.sh

# Cleanup image for disk space
docker container prune -f
docker rmi snowflake_connector_python_image
