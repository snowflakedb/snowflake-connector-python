#!/bin/bash -e

set -o pipefail


export THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export WORKSPACE=${WORKSPACE:-/tmp}

CI_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ -n "$JENKINS_HOME" ]]; then
  ROOT_DIR="$(cd "${CI_DIR}/.." && pwd)"
  export WORKSPACE=${WORKSPACE:-/tmp}
  echo "Use /sbin/ip"
  IP_ADDR=$(/sbin/ip -4 addr show scope global dev eth0 | grep inet | awk '{print $2}' | cut -d / -f 1)

fi

gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output $THIS_DIR/../.github/workflows/parameters/private/parameters_aws_auth_tests.json "$THIS_DIR/../.github/workflows/parameters/private/parameters_aws_auth_tests.json.gpg"
gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output $THIS_DIR/../.github/workflows/parameters/private/rsa_keys/rsa_key.p8 "$THIS_DIR/../.github/workflows/parameters/private/rsa_keys/rsa_key.p8.gpg"
gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output $THIS_DIR/../.github/workflows/parameters/private/rsa_keys/rsa_key_invalid.p8 "$THIS_DIR/../.github/workflows/parameters/private/rsa_keys/rsa_key_invalid.p8.gpg"

docker run \
  -v $(cd $THIS_DIR/.. && pwd):/mnt/host \
  -v $WORKSPACE:/mnt/workspace \
  --rm \
    nexus.int.snowflakecomputing.com:8086/docker/snowdrivers-test-external-browser-python:2 \
  "/mnt/host/ci/container/test_authentication.sh"
