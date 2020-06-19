#!/usr/bin/env bash
#
# Run whitesource for components which need versioning
set -e
set -o pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

[[ -z "$WHITESOURCE_API_KEY" ]] && echo "[WARNING] No WHITESOURCE_API_KEY is set. No WhiteSource scan will occur." && exit 0

if [[ -z "$VIRTUAL_ENV" ]]; then
    PY=
    TMP_VENV=$(mktemp -d)
    if which python3 >& /dev/null; then
        PY=python3
    elif which python3.7 >& /dev/null; then
        PY=python3.7
    elif which python3.6 >& /dev/null; then
        PY=python3.6
    elif which python3.5 >& /dev/null; then
        PY=python3.5
    elif which python >& /dev/null; then
        if [[ "$(python -c 'import sys; print(sys.version_info.major)')" == "3" ]]; then
            PY=python
        fi
    fi
    [[ -z "$PY" ]] && echo "[ERROR] Failed to find Python3" && exit 1

    echo "[INFO] Installing Python Virtualenv"
    $PY -m venv $TMP_VENV >& /dev/null
    source $TMP_VENV/bin/activate
    IS_IN_CUSTOM_VENV=true
else
    echo "[INFO] Using Python Virtualenv $VIRTUAL_ENV"
fi
pip install -U pip virtualenv >& /dev/null

export PRODUCT_NAME=snowflake-connector-python

export PROD_BRANCH=master
export PROJECT_VERSION=$TRAVIS_COMMIT

env | grep TRAVIS | sort

if [[ "$TRAVIS_PULL_REQUEST" != "false" ]]; then
    echo "[INFO] Pull Request"
    export PROJECT_NAME=PR-$TRAVIS_PULL_REQUEST
elif [[ "$TRAVIS_BRANCH" == "$PROD_BRANCH" ]]; then
    echo "[INFO] Production branch"
    export PROJECT_NAME=$PROD_BRANCH
else
    echo "[INFO] Non Production branch. Skipping wss..."
    export PROJECT_NAME=
fi

SCAN_DIRECTORIES=$(cd $THIS_DIR/.. && pwd)

if [[ -n "$PROJECT_NAME" ]]; then
    rm -f wss-unified-agent.jar
    curl -LO https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar
fi
SCAN_CONFIG=wss-agent.config
cat > $SCAN_CONFIG <<CONFIG
###############################################################
# WhiteSource Unified-Agent configuration file
###############################################################
# PYTHON SCAN MODE: setup.py
###############################################################

apiKey=
#userKey is required if WhiteSource administrator has enabled "Enforce user level access" option
#userKey=
#requesterEmail=user@provider.com

projectName=
projectVersion=
projectToken=
#projectTag= key:value

productName=
productVersion=
productToken=

#projectPerFolder=true
#projectPerFolderIncludes=
#projectPerFolderExcludes=

#wss.connectionTimeoutMinutes=60
wss.url=https://saas.whitesourcesoftware.com/agent

############
# Policies #
############
checkPolicies=true
forceCheckAllDependencies=true
forceUpdate=true
forceUpdate.failBuildOnPolicyViolation=true
#updateInventory=false

###########
# General #
###########
#offline=false
#updateType=APPEND
#ignoreSourceFiles=true
#scanComment=
#failErrorLevel=ALL
#requireKnownSha1=false

#generateProjectDetailsJson=true
#generateScanReport=true
#scanReportTimeoutMinutes=10
#scanReportFilenameFormat=

#analyzeFrameworks=true
#analyzeFrameworksReference=

#updateEmptyProject=false

#log.files.level=
#log.files.maxFileSize=
#log.files.maxFilesCount=
#log.files.path=

########################################
# Package Manager Dependency resolvers #
########################################
resolveAllDependencies=false

python.resolveDependencies=true
python.ignoreSourceFiles=false
python.ignorePipInstallErrors=true
python.installVirtualenv=false # set this parameter to true if using virtualenv to build the project
python.resolveHierarchyTree=false
python.resolveSetupPyFiles=true
python.runPipenvPreStep=false
#python.IgnorePipenvInstallErrors=true
python.resolveGlobalPackages=false

###########################################################################################
# Includes/Excludes Glob patterns - Please use only one exclude line and one include line #
###########################################################################################
includes=**/*.egg **/*.whl **/*.py

#Exclude file extensions or specific directories by adding **/*.<extension> or **/<excluded_dir>/**
excludes=**/*sources.jar **/*javadoc.jar

case.sensitive.glob=false
followSymbolicLinks=true
CONFIG

set +e
echo "[INFO] Running wss.sh for ${PRODUCT_NAME}-${PROJECT_NAME} under ${SCAN_DIRECTORIES}"
if [[ "$PROJECT_NAME" == "$PROD_BRANCH" ]]; then
    # Prod branch
    java -jar wss-unified-agent.jar -apiKey ${WHITESOURCE_API_KEY} \
        -c ${SCAN_CONFIG} \
        -d ${SCAN_DIRECTORIES} \
        -product ${PRODUCT_NAME} \
        -project ${PROJECT_NAME} \
        -projectVersion ${PROJECT_VERSION} \
        -offline true
    ERR=$?
    if [[ "$ERR" != "254" && "$ERR" != "0" ]]; then
        echo "failed to run wss for $PRODUCT_VERSION_${PROJECT_VERSION} in ${PROJECT_VERSION}..."
        exit 1
    fi

    java -jar wss-unified-agent.jar -apiKey ${WHITESOURCE_API_KEY} \
       -c ${SCAN_CONFIG} \
       -product ${PRODUCT_NAME} \
       -project ${PROJECT_NAME} \
       -projectVersion baseline \
       -requestFiles whitesource/update-request.txt
    ERR=$?
    if [[ "$ERR" != "254" && "$ERR" != "0" ]]; then
        echo "failed to run wss for $PRODUCT_VERSION_${PROJECT_VERSION} in baseline"
        exit 1
    fi
    java -jar wss-unified-agent.jar -apiKey ${WHITESOURCE_API_KEY} \
        -c ${SCAN_CONFIG} \
        -product ${PRODUCT_NAME} \
        -project ${PROJECT_NAME} \
        -projectVersion ${PROJECT_VERSION} \
        -requestFiles whitesource/update-request.txt
    ERR=$?
    if [[ "$ERR" != "254" && "$ERR" != "0" ]]; then
        echo "failed to run wss for $PRODUCT_VERSION_${PROJECT_VERSION} in ${PROJECT_VERSION}"
        exit 1
    fi
elif [[ -n "$PROJECT_NAME" ]]; then
    # PR
    java -jar wss-unified-agent.jar -apiKey ${WHITESOURCE_API_KEY} \
        -c ${SCAN_CONFIG} \
        -d ${SCAN_DIRECTORIES} \
        -product ${PRODUCT_NAME} \
        -project ${PROJECT_NAME} \
        -projectVersion ${PROJECT_VERSION}
    ERR=$?
    if [[ "$ERR" != "254" && "$ERR" != "0" ]]; then
        echo "failed to run wss for $PRODUCT_VERSION_${PROJECT_VERSION} in ${PROJECT_VERSION}..."
        exit 1
    fi
fi
set -e

[[ -n "$IS_IN_CUSTOM_VENV" ]] && deactivate || true
