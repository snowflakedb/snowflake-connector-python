#!/bin/bash -e

set -o pipefail

export THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export RSA_KEY_PATH_AWS_AZURE="$THIS_DIR/wif/parameters/rsa_wif_aws_azure"
export RSA_KEY_PATH_GCP="$THIS_DIR/wif/parameters/rsa_wif_gcp"
export PARAMETERS_FILE_PATH="$THIS_DIR/wif/parameters/parameters_wif.json"

run_tests_and_set_result() {
  local provider="$1"
  local host="$2"
  local snowflake_host="$3"
  local rsa_key_path="$4"

  ssh -i "$rsa_key_path" -o IdentitiesOnly=yes -p 443 "$host" env BRANCH="$BRANCH" SNOWFLAKE_TEST_WIF_HOST="$snowflake_host" SNOWFLAKE_TEST_WIF_PROVIDER="$provider" SNOWFLAKE_TEST_WIF_ACCOUNT="$SNOWFLAKE_TEST_WIF_ACCOUNT" bash << EOF
      set -e
      set -o pipefail
      docker run \
        --rm \
        -e BRANCH \
        -e SNOWFLAKE_TEST_WIF_PROVIDER \
        -e SNOWFLAKE_TEST_WIF_HOST \
        -e SNOWFLAKE_TEST_WIF_ACCOUNT \
        snowflakedb/client-python-test:1 \
          bash -c "
            echo 'Running tests on branch: \$BRANCH'
            if [[ \"\$BRANCH\" =~ ^PR-[0-9]+\$ ]]; then
              curl -L https://github.com/snowflakedb/snowflake-connector-python/archive/refs/pull/\$(echo \$BRANCH | cut -d- -f2)/head.tar.gz | tar -xz
              mv snowflake-connector-python-* snowflake-connector-python
            else
              curl -L https://github.com/snowflakedb/snowflake-connector-python/archive/refs/heads/\$BRANCH.tar.gz | tar -xz
              mv snowflake-connector-python-\$BRANCH snowflake-connector-python
            fi
            cd snowflake-connector-python
            bash ci/wif/test_wif.sh
          "
EOF
  local status=$?

  if [[ $status -ne 0 ]]; then
    echo "$provider tests failed with exit status: $status"
    EXIT_STATUS=1
  else
    echo "$provider tests passed"
  fi
}

get_branch() {
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ "$branch" == "HEAD" ]]; then
    branch=$(git name-rev --name-only HEAD | sed 's#^remotes/origin/##;s#^origin/##')
  fi
  echo "$branch"
}

setup_parameters() {
  gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output "$RSA_KEY_PATH_AWS_AZURE" "${RSA_KEY_PATH_AWS_AZURE}.gpg"
  gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output "$RSA_KEY_PATH_GCP" "${RSA_KEY_PATH_GCP}.gpg"
  chmod 600 "$RSA_KEY_PATH_AWS_AZURE"
  chmod 600 "$RSA_KEY_PATH_GCP"
  gpg --quiet --batch --yes --decrypt --passphrase="$PARAMETERS_SECRET" --output "$PARAMETERS_FILE_PATH" "${PARAMETERS_FILE_PATH}.gpg"
  eval $(jq -r '.wif | to_entries | map("export \(.key)=\(.value|tostring)")|.[]' $PARAMETERS_FILE_PATH)
}

BRANCH=$(get_branch)
export BRANCH
setup_parameters

# Run tests for all cloud providers
EXIT_STATUS=0
set +e  # Don't exit on first failure
run_tests_and_set_result "AZURE" "$HOST_AZURE" "$SNOWFLAKE_TEST_WIF_HOST_AZURE" "$RSA_KEY_PATH_AWS_AZURE"
run_tests_and_set_result "AWS" "$HOST_AWS" "$SNOWFLAKE_TEST_WIF_HOST_AWS" "$RSA_KEY_PATH_AWS_AZURE"
run_tests_and_set_result "GCP" "$HOST_GCP" "$SNOWFLAKE_TEST_WIF_HOST_GCP" "$RSA_KEY_PATH_GCP"
set -e  # Re-enable exit on error
echo "Exit status: $EXIT_STATUS"
exit $EXIT_STATUS
