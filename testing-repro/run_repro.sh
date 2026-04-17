#!/usr/bin/env bash
#
# Run the testing-repro diagnostic scripts and verify log output.
#
# Usage:
#   ./run_repro.sh                              # run both, use PyPI connector
#   ./run_repro.sh bypass                       # run only bypass_test.py
#   ./run_repro.sh repro                        # run only put_repro.py
#   ./run_repro.sh repro --wheel path/to.whl    # install connector from local wheel
#   ./run_repro.sh --wheel path/to.whl          # run both with local wheel
#
# Before running, create testing-repro/parameters.json from the .example file:
#   cp parameters.json.example parameters.json
#   # then edit parameters.json with your Snowflake credentials
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# --- Parse arguments ---
MODE="all"
WHEEL=""

while [ $# -gt 0 ]; do
    case "$1" in
        all|bypass|repro)
            MODE="$1"; shift ;;
        --wheel)
            if [ -z "${2:-}" ]; then
                echo "ERROR: --wheel requires a path argument"
                exit 1
            fi
            WHEEL="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
            if [ ! -f "$WHEEL" ]; then
                echo "ERROR: wheel not found: $WHEEL"
                exit 1
            fi
            shift 2 ;;
        *)
            echo "Usage: $0 [all|bypass|repro] [--wheel <path-to-wheel>]"
            echo ""
            echo "Modes:"
            echo "  all     run both bypass_test.py and put_repro.py (default)"
            echo "  bypass  run only bypass_test.py (S3 upload bypass)"
            echo "  repro   run only put_repro.py (PUT repro)"
            echo ""
            echo "Options:"
            echo "  --wheel <path>  install snowflake-connector-python from a local wheel"
            echo "                  instead of PyPI (recreates venv)"
            exit 1
            ;;
    esac
done

VENV_DIR="$SCRIPT_DIR/.venv"

# Log files written by the Python scripts themselves (DEBUG level)
BYPASS_LOG="$SCRIPT_DIR/bypass.log"
REPRO_LOG="$SCRIPT_DIR/repro.log"

echo "============================================================"
echo "testing-repro runner  (mode: $MODE)"
echo "============================================================"
echo ""
echo "Working directory : $SCRIPT_DIR"
echo "Parameters file   : $SCRIPT_DIR/parameters.json"
[ -n "$WHEEL" ] && echo "Connector wheel   : $WHEEL"
echo ""

# --- Set up venv ---
NEED_INSTALL=0
if [ -n "$WHEEL" ]; then
    # Always recreate venv when a wheel is specified to ensure correct version
    echo "Recreating venv to install from wheel ..."
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
    NEED_INSTALL=1
elif [ ! -d "$VENV_DIR" ]; then
    echo "Virtual environment not found at $VENV_DIR — creating ..."
    python3 -m venv "$VENV_DIR"
    NEED_INSTALL=1
else
    echo "Using existing venv: $VENV_DIR"
fi

if [ "$NEED_INSTALL" -eq 1 ]; then
    echo "Installing dependencies ..."
    if [ -n "$WHEEL" ]; then
        "$VENV_DIR/bin/pip" install --quiet --force-reinstall "$WHEEL"
    else
        "$VENV_DIR/bin/pip" install --quiet snowflake-connector-python
    fi
    "$VENV_DIR/bin/pip" install --quiet boto3 requests cryptography
    echo "Venv ready."
fi

PYTHON="$VENV_DIR/bin/python"
echo ""

# Show installed connector version
echo "snowflake-connector-python version:"
"$PYTHON" -c "import snowflake.connector; print(f'  {snowflake.connector.__version__}')"
echo ""

# --- Check parameters.json exists ---
if [ ! -f "$SCRIPT_DIR/parameters.json" ]; then
    echo "ERROR: parameters.json not found at $SCRIPT_DIR/parameters.json"
    echo ""
    echo "  Create it by copying the example:"
    echo "    cp $SCRIPT_DIR/parameters.json.example $SCRIPT_DIR/parameters.json"
    echo ""
    echo "  Then fill in your Snowflake credentials."
    exit 1
fi
echo "parameters.json found."
echo ""

# --- Generate sample data files for bypass_test ---
if [ "$MODE" = "all" ] || [ "$MODE" = "bypass" ]; then
    DATA_DIR="$SCRIPT_DIR/data"
    mkdir -p "$DATA_DIR"

    DATA_COUNT=$(find "$DATA_DIR" -maxdepth 1 -type f ! -name '.gitkeep' | wc -l)
    if [ "$DATA_COUNT" -eq 0 ]; then
        echo "No data files found in $DATA_DIR — generating sample files ..."
        dd if=/dev/urandom bs=1024 count=5 of="$DATA_DIR/sample_5kb.bin" 2>/dev/null
        dd if=/dev/urandom bs=1024 count=50 of="$DATA_DIR/sample_50kb.bin" 2>/dev/null
        head -c 1024 /dev/urandom | base64 > "$DATA_DIR/sample_text.txt"
        echo "  Created: sample_5kb.bin, sample_50kb.bin, sample_text.txt"
    else
        echo "Data directory    : $DATA_DIR ($DATA_COUNT files)"
    fi
    echo ""
fi

# --- Run bypass_test.py ---
if [ "$MODE" = "all" ] || [ "$MODE" = "bypass" ]; then
    echo "============================================================"
    echo "Running bypass_test.py ..."
    echo "  Debug log (written by script): $BYPASS_LOG"
    echo "============================================================"
    "$PYTHON" "$SCRIPT_DIR/bypass_test.py"
    echo ""

    if [ -f "$BYPASS_LOG" ]; then
        LINES=$(wc -l < "$BYPASS_LOG")
        echo "bypass_test.py debug log: $BYPASS_LOG ($LINES lines)"
    else
        echo "WARNING: bypass_test.py did not produce log at $BYPASS_LOG"
    fi
    echo ""
fi

# --- Run put_repro.py ---
if [ "$MODE" = "all" ] || [ "$MODE" = "repro" ]; then
    echo "============================================================"
    echo "Running put_repro.py ..."
    echo "  Debug log (written by script): $REPRO_LOG"
    echo "============================================================"
    "$PYTHON" "$SCRIPT_DIR/put_repro.py"
    echo ""

    if [ -f "$REPRO_LOG" ]; then
        LINES=$(wc -l < "$REPRO_LOG")
        echo "put_repro.py debug log: $REPRO_LOG ($LINES lines)"
    else
        echo "WARNING: put_repro.py did not produce log at $REPRO_LOG"
    fi
fi

echo ""
echo "============================================================"
echo "Done. Debug log files (full DEBUG output):"
[ "$MODE" = "all" ] || [ "$MODE" = "bypass" ] && echo "  bypass : $BYPASS_LOG"
[ "$MODE" = "all" ] || [ "$MODE" = "repro" ]  && echo "  repro  : $REPRO_LOG"
echo "============================================================"
