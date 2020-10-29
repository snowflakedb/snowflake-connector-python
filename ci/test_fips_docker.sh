#!/bin/bash -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
# In case this is not run locally and not on Jenkins

if [[ ! -d "$CONNECTOR_DIR/dist/" ]] || [[ $(ls $CONNECTOR_DIR/dist/*cp36*manylinux2010*.whl) == '' ]]; then
  echo "Missing wheel files, going to compile Python connector in Docker..."
  $THIS_DIR/build_docker.sh 3.6
  cp $CONNECTOR_DIR/dist/repaired_wheels/*cp36*manylinux2010*.whl $CONNECTOR_DIR/dist/
fi

cd $THIS_DIR/docker/connector_test_fips

CONTAINER_NAME=test_fips_connector

echo "[Info] Start building docker image"
docker build -t ${CONTAINER_NAME}:1.0 -f Dockerfile .

user_id=$(id -u $USER)
docker run --network=host \
    -e LANG=en_US.UTF-8 \
    -e TERM=vt102 \
    -e SF_USE_OPENSSL_ONLY=True \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    -e CRYPTOGRAPHY_ALLOW_OPENSSL_102=1 \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e SF_REGRESS_LOGS \
    -e SF_PROJECT_ROOT \
    -e cloud_provider \
    --mount type=bind,source="${CONNECTOR_DIR}",target=/home/user/snowflake-connector-python \
    ${CONTAINER_NAME}:1.0 \
    /home/user/snowflake-connector-python/ci/test_fips.sh $1
