#!/usr/bin/env bash
#
# Run the testing-repro diagnostic scripts and verify log output.
#
# Usage:
#   ./run_repro.sh                              # run both, auto-detect wheel/ dir
#   ./run_repro.sh bypass                       # run only bypass_test.py
#   ./run_repro.sh repro                        # run only put_repro.py
#   ./run_repro.sh repro --wheel path/to.whl    # install connector from specific wheel
#
# By default the script looks for a .whl file in the wheel/ subdirectory.
# If found, it installs from that wheel; otherwise it falls back to PyPI.
#
# All debug logs are written to the logs/ subdirectory.
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
FORCE_REINSTALL=0

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
        --force-reinstall)
            FORCE_REINSTALL=1; shift ;;
        *)
            echo "Usage: $0 [all|bypass|repro] [--wheel <path>] [--force-reinstall]"
            echo ""
            echo "Modes:"
            echo "  all     run both bypass_test.py and put_repro.py (default)"
            echo "  bypass  run only bypass_test.py (S3 upload bypass)"
            echo "  repro   run only put_repro.py (PUT repro)"
            echo ""
            echo "Options:"
            echo "  --wheel <path>      install connector from a specific wheel"
            echo "  --force-reinstall   recreate venv and reinstall everything"
            echo ""
            echo "By default, looks for a .whl in wheel/ — falls back to PyPI if not found."
            echo "Logs are written to logs/ subdirectory."
            exit 1
            ;;
    esac
done

# --- Auto-detect wheel from wheel/ directory if --wheel not given ---
if [ -z "$WHEEL" ]; then
    WHEEL_DIR="$SCRIPT_DIR/wheel"
    if [ -d "$WHEEL_DIR" ]; then
        # Pick the newest .whl file
        FOUND_WHEEL="$(ls -t "$WHEEL_DIR"/*.whl 2>/dev/null | head -1 || true)"
        if [ -n "$FOUND_WHEEL" ]; then
            WHEEL="$FOUND_WHEEL"
            echo "Auto-detected wheel: $WHEEL"
        fi
    fi
fi

VENV_DIR="$SCRIPT_DIR/.venv"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Log file paths
BYPASS_LOG="$LOG_DIR/bypass.log"
REPRO_LOG="$LOG_DIR/repro.log"

echo "============================================================"
echo "testing-repro runner  (mode: $MODE)"
echo "============================================================"
echo ""
echo "Working directory : $SCRIPT_DIR"
echo "Parameters file   : $SCRIPT_DIR/parameters.json"
echo "Log directory     : $LOG_DIR"
if [ -n "$WHEEL" ]; then
    echo "Connector wheel   : $WHEEL"
else
    echo "Connector source  : PyPI (no wheel found in wheel/)"
fi
echo ""

# --- Set up venv ---
NEED_INSTALL=0
if [ "$FORCE_REINSTALL" -eq 1 ] || [ -n "$WHEEL" ]; then
    echo "Recreating venv ..."
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

# Show installed connector version and full environment
echo "snowflake-connector-python version:"
"$PYTHON" -c "import snowflake.connector; print(f'  {snowflake.connector.__version__}')"
FREEZE_FILE="$LOG_DIR/pip_freeze.txt"
"$VENV_DIR/bin/pip" freeze > "$FREEZE_FILE"
echo "pip freeze saved to: $FREEZE_FILE"
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
    echo "  Debug log: $BYPASS_LOG"
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
    echo "  Debug log: $REPRO_LOG"
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
echo "Done. Debug log files in $LOG_DIR:"
[ "$MODE" = "all" ] || [ "$MODE" = "bypass" ] && echo "  bypass : $BYPASS_LOG"
[ "$MODE" = "all" ] || [ "$MODE" = "repro" ]  && echo "  repro  : $REPRO_LOG"
echo "============================================================"
