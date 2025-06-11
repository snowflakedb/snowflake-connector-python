
# Before running, do something similar to the following in command line.
# export build_name=snowflake-connector-python-3.999.0-py39h123;
# export WORKSPACE=/home/zyao/playground;
# export build_number=321;

# Here miniconda.sh is just a installer that I downloaded from Anaconda official site,
# https://repo.anaconda.com/miniconda/


if [[ -z $WORKSPACE ]]; then
  # Development on dev machine
  WORKSPACE=$HOME
fi

DIRECTORY=`dirname $0`

# ===== Build docker image =====
cd $DIRECTORY

cp /home/zyao/miniconda-install/miniconda.sh ./miniconda_anaconda_aarch64.sh

docker build -t snowflake_connector_python_anaconda_aarch64 -f Dockerfile .

rm miniconda_anaconda_aarch64.sh || true
# Go back to the original directory
cd $DIRECTORY


# Check to make sure repos exist to build conda packages
if [[ -d $WORKSPACE/snowflake-connector-python ]]; then
  echo "Check snowflake-connector-python repo exists - PASSED"
else
  echo "[FAILURE] Please clone snowflake-connector-python repo at $WORKSPACE/snowflake-connector-python"
fi

export PKG_NAME=${build_name}-linux-aarch64.tar.gz

# Run packager in docker image
docker run \
  -v $WORKSPACE/snowflake-connector-python/:/repo/snowflake-connector-python \
  -v $WORKSPACE/conda-bld:/repo/conda-bld \
  -e build_name=${build_name} \
  -e PYTHON=/etc/miniconda/bin/python \
  -e PYTHON=python \
  -e SNOWFLAKE_CONNECTOR_PYTHON_BUILD_NUMBER=${build_number} \
  snowflake_connector_python_anaconda_aarch64 \
  /repo/snowflake-connector-python/ci/conda/package_builder.sh

# Cleanup image for disk space
docker container prune -f
docker rmi snowflake_connector_python_anaconda_aarch64
