
# Before running, do something similar to the following in command line.
# export WORKSPACE=/home/zyao/my_workspace;
# export package_build_number=321;

# Here miniconda-install.sh is just a installer that I downloaded from Anaconda official site,
# https://repo.anaconda.com/miniconda/


if [[ -z $WORKSPACE ]]; then
  # Development on dev machine
  WORKSPACE=$HOME
fi

# ===== Build docker image =====
cd $WORKSPACE

docker build --build-arg ARCH=$(uname -m) -t snowflake_connector_python_image -f snowflake-connector-python/ci/anaconda/Dockerfile .

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
  -u $(id -u):$(id -g) \
  -v $WORKSPACE/snowflake-connector-python/:/repo/snowflake-connector-python \
  -v $WORKSPACE/conda-bld:/repo/conda-bld \
  -e SNOWFLAKE_CONNECTOR_PYTHON_BUILD_NUMBER=${package_build_number} \
  snowflake_connector_python_image \
  /repo/snowflake-connector-python/ci/anaconda/package_builder.sh

# Cleanup image for disk space
docker container prune -f
docker rmi snowflake_connector_python_image
