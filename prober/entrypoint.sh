#!/bin/bash

# Initialize an empty string to hold all parameters
python_version=""
connector_version=""
params=""

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == "--python_version" ]]; then
        python_version="$2"
        shift 2
    elif [[ "$1" == "--connector_version" ]]; then
        connector_version="$2"
        shift 2
    else
        params+="$1 $2 "
        shift 2
    fi
done

# Construct the virtual environment path
venv_path="/venvs/python_${python_version}_connector_${connector_version}"

# Check if the virtual environment exists
if [[ ! -d "$venv_path" ]]; then
    echo "Error: Virtual environment not found at $venv_path"
    exit 1
fi

# Run main.py with given venv
echo "Running main.py with virtual environment: $venv_path"
source "$venv_path/bin/activate"
prober $params
deactivate
