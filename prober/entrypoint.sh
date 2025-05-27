#!/bin/bash

JSON_FILE="/prober/parameters.json"

# Iterate through each key-value pair in the JSON file
while IFS="=" read -r key value; do
    # Export the key-value pair as an environment variable
    export "$key"="$value"
    echo "Exported: $key=$value"
done < <(jq -r 'to_entries | .[] | "\(.key)=\(.value)"' "$JSON_FILE")

# Run main.py with all available virtual environments
for venv in /venvs/*; do
    echo "Running main.py with virtual environment: $(basename $venv)"
    source $venv/bin/activate
    pip install -e /prober
    prober --scope $scope --host $host --port $port --role $role --account $account --schema $schema --warehouse $warehouse --user $user --private_key $private_key
    deactivate
done
