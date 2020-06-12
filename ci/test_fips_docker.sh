#!/bin/bash -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONNECTOR_DIR="$( dirname "${THIS_DIR}")"
# In case this is not run locally and not on Jenkins
WORKSPACE=${WORKSPACE:-$HOME}

# If running on Jenkins then default to AWS and change to others if cloud_provider is set
if [[ -n $JENKINS_URL ]]; then
  PARAMS_FILE="$WORKSPACE/Tests/ClientsPerf/parameters/parameters_aws_python.json.gpg"
  [ $cloud_provider == azure ] && PARAMS_FILE="$WORKSPACE/Tests/ClientsPerf/parameters/parameters_azure_python.json.gpg"
  [ $cloud_provider == gcp ] && PARAMS_FILE="$WORKSPACE/Tests/ClientsPerf/parameters/parameters_gcp_python.json.gpg"
  gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" $PARAMS_FILE | jq '{account: .testconnection.SNOWFLAKE_TEST_ACCOUNT, user: .testconnection.SNOWFLAKE_TEST_USER, password: .testconnection.SNOWFLAKE_TEST_PASSWORD, schema: .testconnection.SNOWFLAKE_TEST_SCHEMA, database: .testconnection.SNOWFLAKE_TEST_DATABASE, protocol: "https", host: (.testconnection.SNOWFLAKE_TEST_ACCOUNT + ".snowflakecomputing.com"), warehouse: .testconnection.SNOWFLAKE_TEST_WAREHOUSE, port: 443, role: .testconnection.SNOWFLAKE_TEST_ROLE}' | sed '1s;^;CONNECTION_PARAMETERS = ;' > test/parameters.py
fi

if [ ! -d "$CONNECTOR_DIR/dist/docker/repaired_wheels/" ] || [ $(ls "$CONNECTOR_DIR/dist/docker/repaired_wheels/*36*" ) -eq 0 ]; then
  echo "Missing wheel files, going to compile Python connector in Docker..."
  $THIS_DIR/build_docker.sh
fi

cd $THIS_DIR/docker/connector_test_fips

echo "[Info] Start building docker image"
docker build -t test_fips_connector:1.0 -f Dockerfile .

user_id=$(id -u $USER)
docker run --network=host \
    -e LANG=en_US.UTF-8 \
    -e TERM=vt102 \
    -e SF_USE_OPENSSL_ONLY=True \
    -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -e LOCAL_USER_ID=$user_id \
    -e AWS_ACCESS_KEY_ID \
    -e AWS_SECRET_ACCESS_KEY \
    -e SF_REGRESS_LOGS \
    -e SF_PROJECT_ROOT \
    -e WORKSPACE \
    --mount type=bind,source="$WORKSPACE",target="$WORKSPACE" \
    test_fips_connector:1.0 \
    ${THIS_DIR}/test_fips.sh $1
