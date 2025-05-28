#!/bin/bash


# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --scope) scope="$2"; shift ;;
        --host) host="$2"; shift ;;
        --port) port="$2"; shift ;;
        --role) role="$2"; shift ;;
        --account) account="$2"; shift ;;
        --schema) schema="$2"; shift ;;
        --warehouse) warehouse="$2"; shift ;;
        --user) user="$2"; shift ;;
        --private_key) private_key="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Validate required parameters
if [[ -z "$scope" || -z "$host" || -z "$port" || -z "$role" || -z "$account" || -z "$schema" || -z "$warehouse" || -z "$user" || -z "$private_key" ]]; then
    echo "Error: Missing required parameters."
    exit 1
fi


# Run main.py with all available virtual environments
for venv in /venvs/*; do
    echo "Running main.py with virtual environment: $(basename $venv)"
    source $venv/bin/activate
    pip install -e /prober
    prober --scope $scope --host $host --port $port --role $role --account $account --schema $schema --warehouse $warehouse --user $user --private_key $private_key
    deactivate
done
