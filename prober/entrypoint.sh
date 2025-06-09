#!/bin/bash

# Initialize an empty string to hold all parameters
params=""

# Parse command-line arguments dynamically
while [[ "$#" -gt 0 ]]; do
    params="$params $1 $2"
    shift 2
done

# Run main.py within all available virtual environments
for venv in /venvs/*; do
    echo "Running main.py with virtual environment: $(basename "$venv")"
    source "$venv/bin/activate"
    prober $params
    deactivate
done
