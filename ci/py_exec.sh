#!/bin/bash
PYTHON_EXEC=${PYTHON_EXEC:-}
PYTHON_EXEC_FULL_PATH=${PYTHON_EXEC_FULL_PATH:-}
PYTHON_ENV=${PYTHON_ENV:-}

function set_defaults() {
  # Set up to fall back onto when something is set wrong, or PYTHON_ENV is invalid
  PYTHON_EXEC=python3.5
  find_full_path ${PYTHON_EXEC}
  get_python_env_from_exec ${PYTHON_EXEC}
}

function verify_python_env() {
  local env=$1
  echo $(python -c "e='${env}';print(len(e)==2 and all([c in '0123456789' for c in e]))")
}

function get_python_env_from_exec() {
  local exec=$1

  PYTHON_ENV=$(${exec} -c "import sys; print(str().join([str(e) for e in sys.version_info[:2]]))")

  if [[ $? -ne 0 ]]; then
    echo "ERROR: could no determine PYTHON_ENV with PYTHON_EXEC=${PYTHON_EXEC}"
    exit 2
  fi
}

function get_python_exec_from_env() {
  # Note: we expect version in this form: "36"
  local version=$1

  full_version=$(python -c "v='${version}';print('.'.join(v))")
  PYTHON_EXEC=python${full_version}
  find_full_path $PYTHON_EXEC
}

function find_full_path() {
  local exec=$1

  PYTHON_EXEC_FULL_PATH=$(command -v ${exec})
  find_exec=$?
  if [[ $find_exec -ne 0 ]]; then
    echo "ERROR: ${exec} does not exist"
    exit 1
  fi
}

if [[ -n "$PYTHON_EXEC" && -z "$PYTHON_ENV" ]]; then
  # Only PYTHON_EXEC is set before
  find_full_path $PYTHON_EXEC
  get_python_env_from_exec $PYTHON_EXEC
elif [[ -n "$PYTHON_ENV" && -z "$PYTHON_EXEC" ]]; then
  # Only PYTHON_ENV is set before
  get_python_exec_from_env "$PYTHON_ENV"
elif [[ -n "$PYTHON_EXEC" && -n "$PYTHON_ENV" ]]; then
  echo "WARN: Both PYTHON_EXEC and PYTHON_ENV is set beforehand, assuming that you know what you are doing"
  find_full_path $PYTHON_EXEC
else
  # Set defaults, nothing was set before calling this script
  set_defaults
fi

# Virtualenv functions
function resetup_env() {
  # no matter what setup a fresh virtual environment at $1
  local env=$1

  if [[ -n "$env" ]]; then
    if [[ -d "$env" ]]; then
      rm -rf "$env"
    fi
      run_cmd "$PYTHON_EXEC -m venv $env" "build_tools.log"
      source "$env/bin/activate"
      run_cmd "pip install -U pip setuptools" "build_tools.log"
      deactivate
  fi

}

function setup_env() {
  # like resetup_build_env but only if it doesn't already exist
  local env=$1

  if [[ ! -d "$env" ]]; then
    resetup_env "$env"
  fi
}


# Success

echo "PYTHON_EXEC=${PYTHON_EXEC}"
echo "PYTHON_EXEC_FULL_PATH=${PYTHON_EXEC_FULL_PATH}"
echo "PYTHON_ENV=${PYTHON_ENV}"
export PYTHON_EXEC
export PYTHON_EXEC_FULL_PATH
export PYTHON_ENV
