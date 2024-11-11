#!/bin/bash -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
PYTHON_VERSION="${1:-3.9}"
PYTHON_SHORT_VERSION="$(echo "$PYTHON_VERSION" | tr -d .)"
# In case this is not run locally and not on Jenkins

if [[ ! -d "$CONNECTOR_DIR/dist/" ]] || [[ $(ls $CONNECTOR_DIR/dist/*cp${PYTHON_SHORT_VERSION}*manylinux2014*.whl) == '' ]]; then
  echo "Missing wheel files, going to compile Python connector in Docker..."
  $THIS_DIR/build_docker.sh $PYTHON_VERSION
  cp $CONNECTOR_DIR/dist/repaired_wheels/*cp${PYTHON_SHORT_VERSION}*manylinux2014*.whl $CONNECTOR_DIR/dist/
fi

cd $THIS_DIR/docker/connector_test_lambda

CONTAINER_NAME="test_lambda_connector${PYTHON_SHORT_VERSION}"
DOCKERFILE="Dockerfile${PYTHON_SHORT_VERSION}"

echo "[Info] Start building lambda docker image"
docker build -t ${CONTAINER_NAME}:1.0 -f ${DOCKERFILE} .

user_id=$(id -u $USER)

docker run --network=host \
    -e LANG=en_US.UTF-8 \
    -e TERM=vt102 \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    -e CRYPTOGRAPHY_ALLOW_OPENSSL_102=1 \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e SF_REGRESS_LOGS \
    -e SF_PROJECT_ROOT \
    -e cloud_provider \
    -e PYTEST_ADDOPTS \
    -e GITHUB_ACTIONS \
    --mount type=bind,source="${CONNECTOR_DIR}",target=/home/user/snowflake-connector-python \
    ${CONTAINER_NAME}:1.0 &

# sleep for sometime to make sure docker run is up and running
sleep 5

# call the lambda function
lambda_result=$(curl -XPOST "http://localhost:8080/2015-03-31/functions/function/invocations" -d '{}')
echo "Lambda result:$lambda_result"

# stop all docker processes
docker stop $(docker ps -a -q)

# reflect status of the test on the job
status=$(echo "$lambda_result" | grep SUCCESS)
if [[ -z "$status" ]]; then
    exit 1
fi
