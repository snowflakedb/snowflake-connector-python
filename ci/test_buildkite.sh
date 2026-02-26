#!/bin/bash -e
#
# Buildkite entry point for Python Connector tests against a local SUT.
#
# Env vars from SUT agent extensions (automatic):
#   SF_REGRESS_GLOBAL_SERVICES_IP   - dynamic SUT hostname
#   SF_REGRESS_GLOBAL_SERVICES_PORT - SUT port
#   SF_ACCOUNT                      - account name (default: testaccount)
#
# Env vars from pipeline step (optional overrides):
#   SF_REGRESS_USER, SF_REGRESS_PASSWORD, SF_REGRESS_SCHEMA,
#   SF_REGRESS_DATABASE, SF_REGRESS_PROTOCOL,
#   python_env, py_test_mode

set -eo pipefail
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONNECTOR_DIR="$(dirname "${THIS_DIR}")"
cd "${CONNECTOR_DIR}"

for var in SF_REGRESS_GLOBAL_SERVICES_IP SF_REGRESS_GLOBAL_SERVICES_PORT; do
    if [ -z "${!var}" ]; then
        echo "ERROR: ${var} is not set."
        exit 1
    fi
done

HOST="${SF_REGRESS_GLOBAL_SERVICES_IP}"
PORT="${SF_REGRESS_GLOBAL_SERVICES_PORT}"
ACCOUNT="${SF_ACCOUNT:-testaccount}"
SF_USER="${SF_REGRESS_USER:-snowman}"
PASSWORD="${SF_REGRESS_PASSWORD:-test}"
SCHEMA="${SF_REGRESS_SCHEMA:-testschema}"
DATABASE="${SF_REGRESS_DATABASE:-testdb}"
PROTOCOL="${SF_REGRESS_PROTOCOL:-http}"

echo "=== SUT Connection ==="
echo "  Host:     ${HOST}"
echo "  Port:     ${PORT}"
echo "  Account:  ${ACCOUNT}"
echo "  User:     ${SF_USER}"
echo "  Protocol: ${PROTOCOL}"
echo "======================"

cat > test/parameters.py <<PYEOF
CONNECTION_PARAMETERS = {
    'account': '${ACCOUNT}',
    'user': '${SF_USER}',
    'password': '${PASSWORD}',
    'schema': '${SCHEMA}',
    'database': '${DATABASE}',
    'protocol': '${PROTOCOL}',
    'host': '${HOST}',
    'port': '${PORT}',
}
PYEOF

echo "[Info] Generated test/parameters.py"

cp test/parameters.py test/parameters_jenkins.py
echo "[Info] Generated test/parameters_jenkins.py (copy for Jenkins compatibility)"

echo "${PASSWORD}" > test/snowflake_ssm_rt.txt
export CLIENT_KNOWN_SSM_FILE_PATH_DOCKER="${CONNECTOR_DIR}/test/snowflake_ssm_rt.txt"

# Download pre-built wheel from S3 (mirrors Jenkins ci/test.sh)
# Jenkins stores branches without origin/ prefix (e.g., "main" not "origin/main")
client_git_branch="$(git rev-parse --abbrev-ref HEAD)"
client_git_commit=$(git rev-parse HEAD)

echo "[Info] Downloading wheel artifacts from S3..."
echo "  Branch: ${client_git_branch}"
echo "  Commit: ${client_git_commit}"

S3_BASE="s3://sfc-eng-jenkins/repository/python_connector/linux"
mkdir -p dist

# Try exact branch+commit first
aws s3 cp --recursive --only-show-errors "${S3_BASE}/${client_git_branch}/${client_git_commit}/" dist || true

# If empty, try branch latest_commit
if [ -z "$(ls -A dist/ 2>/dev/null)" ]; then
    echo "[WARN] No artifacts for exact commit, trying latest_commit for branch..."
    latest_commit=$(aws s3 cp "${S3_BASE}/${client_git_branch}/latest_commit" - 2>/dev/null || true)
    if [ -n "$latest_commit" ]; then
        echo "[Info] Using latest_commit: ${latest_commit}"
        aws s3 cp --recursive --only-show-errors "${S3_BASE}/${client_git_branch}/${latest_commit}/" dist || true
    fi
fi

# If still empty, fall back to main branch
if [ -z "$(ls -A dist/ 2>/dev/null)" ]; then
    echo "[WARN] No artifacts for branch ${client_git_branch}, falling back to main..."
    latest_commit=$(aws s3 cp "${S3_BASE}/main/latest_commit" - 2>/dev/null || true)
    if [ -n "$latest_commit" ]; then
        echo "[Info] Using main latest_commit: ${latest_commit}"
        aws s3 cp --recursive --only-show-errors "${S3_BASE}/main/${latest_commit}/" dist || true
    fi
fi

# Final check
if [ -z "$(ls -A dist/ 2>/dev/null)" ]; then
    echo "[ERROR] No wheel artifacts found in S3"
    exit 1
fi

echo "[Info] Downloaded artifacts:"
ls -la dist/

if [ "${py_test_mode}" = "fips" ]; then
    ${THIS_DIR}/test_fips_docker.sh
else
    ${THIS_DIR}/test_docker.sh ${python_env:-3.9}
fi
