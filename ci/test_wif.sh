#!/bin/bash -e

set -o pipefail

export THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export RSA_KEY_PATH_AWS_AZURE="$THIS_DIR/wif/parameters/rsa_wif_aws_azure"
export RSA_KEY_PATH_GCP="$THIS_DIR/wif/parameters/rsa_wif_gcp"
export PARAMETERS_FILE_PATH="$THIS_DIR/wif/parameters/parameters_wif.json"

run_tests_on_aks() {
  local cluster="$1"
  local service_account="$2"
  local snowflake_host="$3"
  local snowflake_user="$4"
  local description="$5"
  local test_name="$6"

  local pod_name="wif-test-$(date +%s)"

  echo "Running AKS tests ($description) on cluster $cluster"

  ssh -i "$RSA_KEY_PATH_AWS_AZURE" -o IdentitiesOnly=yes -p 443 "$HOST_AKS" \
    BRANCH="$BRANCH" \
    CLUSTER="$cluster" \
    SERVICE_ACCOUNT="$service_account" \
    SNOWFLAKE_TEST_WIF_HOST="$snowflake_host" \
    SNOWFLAKE_TEST_WIF_ACCOUNT="$SNOWFLAKE_TEST_WIF_ACCOUNT" \
    SNOWFLAKE_TEST_WIF_USERNAME="$snowflake_user" \
    TEST_NAME="$test_name" \
    POD_NAME="$pod_name" \
    bash << 'SSHEOF'
      set -e
      set -o pipefail

      kubectl config use-context "$CLUSTER"

      cat <<PODEOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  namespace: default
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: $SERVICE_ACCOUNT
  restartPolicy: Never
  containers:
  - name: test
    image: python:3.11
    command: ["sleep", "3600"]
    volumeMounts:
    - name: snowflake-token
      mountPath: /var/run/secrets/snowflake
  volumes:
  - name: snowflake-token
    projected:
      sources:
      - serviceAccountToken:
          audience: snowflakecomputing.com
          expirationSeconds: 3600
          path: token
PODEOF

      kubectl wait --for=condition=ready pod/"$POD_NAME" --timeout=120s

      kubectl exec "$POD_NAME" -- bash -c "
        apt-get update -q && apt-get install git g++ -y -q
        if [[ '$BRANCH' =~ ^PR-[0-9]+\$ ]]; then
          curl -sL https://github.com/snowflakedb/snowflake-connector-python/archive/refs/pull/$(echo $BRANCH | cut -d- -f2)/head.tar.gz | tar -xz
          mv snowflake-connector-python-* snowflake-connector-python
        else
          curl -sL https://github.com/snowflakedb/snowflake-connector-python/archive/refs/heads/$BRANCH.tar.gz | tar -xz
          mv snowflake-connector-python-$BRANCH snowflake-connector-python
        fi
        cd snowflake-connector-python
        pip install -e '.[azure]' pytest -q
        SF_OCSP_TEST_MODE=true \
        RUN_WIF_TESTS=true \
        SNOWFLAKE_TEST_WIF_HOST=$SNOWFLAKE_TEST_WIF_HOST \
        SNOWFLAKE_TEST_WIF_ACCOUNT=$SNOWFLAKE_TEST_WIF_ACCOUNT \
        SNOWFLAKE_TEST_WIF_USERNAME=$SNOWFLAKE_TEST_WIF_USERNAME \
        SNOWFLAKE_TEST_WIF_PROVIDER=AZURE \
        python -m pytest test/wif/test_wif.py::$TEST_NAME -v
      "
      status=$?
      kubectl delete pod "$POD_NAME" --ignore-not-found
      exit $status
SSHEOF

  local status=$?
  if [[ $status -ne 0 ]]; then
    echo "AKS tests ($description) failed with exit status: $status"
    EXIT_STATUS=1
  else
    echo "AKS tests ($description) passed"
  fi
}

run_tests_and_set_result() {
  local provider="$1"
  local host="$2"
  local snowflake_host="$3"
  local rsa_key_path="$4"
  local snowflake_user="$5"
  local impersonation_path="$6"
  local snowflake_user_for_impersonation="$7"

  ssh -i "$rsa_key_path" -o IdentitiesOnly=yes -p 443 "$host" env BRANCH="$BRANCH" SNOWFLAKE_TEST_WIF_HOST="$snowflake_host" SNOWFLAKE_TEST_WIF_PROVIDER="$provider" SNOWFLAKE_TEST_WIF_ACCOUNT="$SNOWFLAKE_TEST_WIF_ACCOUNT" SNOWFLAKE_TEST_WIF_USERNAME="$snowflake_user" SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH="$impersonation_path" SNOWFLAKE_TEST_WIF_USERNAME_IMPERSONATION="$snowflake_user_for_impersonation" bash << EOF
      set -e
      set -o pipefail
      docker run \
        --rm \
        --cpus=1 \
        -m 1g \
        -e BRANCH \
        -e SNOWFLAKE_TEST_WIF_PROVIDER \
        -e SNOWFLAKE_TEST_WIF_HOST \
        -e SNOWFLAKE_TEST_WIF_ACCOUNT \
        -e SNOWFLAKE_TEST_WIF_USERNAME \
        -e SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH \
        -e SNOWFLAKE_TEST_WIF_USERNAME_IMPERSONATION \
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
  if [[ -n "${GIT_BRANCH}" ]]; then
    # Jenkins
    branch="${GIT_BRANCH}"
  else
    # Local
    branch=$(git rev-parse --abbrev-ref HEAD)
  fi
  echo "${branch}"
}

setup_parameters() {
  source "$THIS_DIR/setup_gpg_home.sh"
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
run_tests_and_set_result "AZURE" "$HOST_AZURE" "$SNOWFLAKE_TEST_WIF_HOST_AZURE" "$RSA_KEY_PATH_AWS_AZURE" "$SNOWFLAKE_TEST_WIF_USERNAME_AZURE" "$SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH_AZURE" "$SNOWFLAKE_TEST_WIF_USERNAME_AZURE_IMPERSONATION"
run_tests_and_set_result "AWS" "$HOST_AWS" "$SNOWFLAKE_TEST_WIF_HOST_AWS" "$RSA_KEY_PATH_AWS_AZURE" "$SNOWFLAKE_TEST_WIF_USERNAME_AWS" "$SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH_AWS" "$SNOWFLAKE_TEST_WIF_USERNAME_AWS_IMPERSONATION"
run_tests_and_set_result "GCP" "$HOST_GCP" "$SNOWFLAKE_TEST_WIF_HOST_GCP" "$RSA_KEY_PATH_GCP" "$SNOWFLAKE_TEST_WIF_USERNAME_GCP" "$SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH_GCP" "$SNOWFLAKE_TEST_WIF_USERNAME_GCP_IMPERSONATION"
run_tests_on_aks "$SNOWFLAKE_TEST_WIF_AKS_CLUSTER_1" "$SNOWFLAKE_TEST_WIF_AKS_SA_MI" "$SNOWFLAKE_TEST_WIF_HOST_AKS" "$SNOWFLAKE_TEST_WIF_USERNAME_AKS" "AKS MI cluster 1" "test_aks_mi_native_auth"
run_tests_on_aks "$SNOWFLAKE_TEST_WIF_AKS_CLUSTER_1" "$SNOWFLAKE_TEST_WIF_AKS_SA_SP" "$SNOWFLAKE_TEST_WIF_HOST_AKS" "$SNOWFLAKE_TEST_WIF_USERNAME_AKS_SP" "AKS SP cluster 1" "test_aks_sp_direct_auth"
run_tests_on_aks "$SNOWFLAKE_TEST_WIF_AKS_CLUSTER_1" "$SNOWFLAKE_TEST_WIF_AKS_SA_MI" "$SNOWFLAKE_TEST_WIF_HOST_AKS" "$SNOWFLAKE_TEST_WIF_USERNAME_AKS_OIDC" "AKS OIDC cluster 1" "test_aks_oidc_backward_compat"
run_tests_on_aks "$SNOWFLAKE_TEST_WIF_AKS_CLUSTER_2" "$SNOWFLAKE_TEST_WIF_AKS_SA_MI" "$SNOWFLAKE_TEST_WIF_HOST_AKS" "$SNOWFLAKE_TEST_WIF_USERNAME_AKS" "AKS MI cluster 2" "test_aks_mi_native_auth"
set -e  # Re-enable exit on error
echo "Exit status: $EXIT_STATUS"
exit $EXIT_STATUS
