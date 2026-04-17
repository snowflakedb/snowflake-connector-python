#!/usr/bin/env bash
#
# Run the testing-repro diagnostic scripts and verify log output.
#
# Prerequisites:
#   pip install snowflake-connector-python boto3 requests cryptography
#
# Before running, create testing-repro/parameters.json from the .example file:
#   cp parameters.json.example parameters.json
#   # then edit parameters.json with your Snowflake credentials
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BYPASS_LOG="$SCRIPT_DIR/test-upload-bypass.log"
PUT_LOG="$SCRIPT_DIR/put_repro.log"

echo "============================================================"
echo "testing-repro runner"
echo "============================================================"
echo ""
echo "Working directory : $SCRIPT_DIR"
echo "Parameters file   : $SCRIPT_DIR/parameters.json"
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
DATA_DIR="$SCRIPT_DIR/data"
mkdir -p "$DATA_DIR"

# Only generate if no real data files exist (ignore .gitkeep)
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

# --- Run bypass_test.py ---
echo "============================================================"
echo "[1/2] Running bypass_test.py ..."
echo "  Log file: $BYPASS_LOG"
echo "============================================================"
python "$SCRIPT_DIR/bypass_test.py" 2>&1 | tee "$SCRIPT_DIR/bypass_test_console.log"
echo ""

if [ -f "$BYPASS_LOG" ]; then
    LINES=$(wc -l < "$BYPASS_LOG")
    echo "bypass_test.py log written: $BYPASS_LOG ($LINES lines)"
else
    echo "WARNING: bypass_test.py did not produce log at $BYPASS_LOG"
fi
echo ""

# --- Run put_repro.py ---
echo "============================================================"
echo "[2/2] Running put_repro.py ..."
echo "  Log file: $PUT_LOG"
echo "============================================================"
python "$SCRIPT_DIR/put_repro.py" 2>&1 | tee "$PUT_LOG"
echo ""

if [ -f "$PUT_LOG" ]; then
    LINES=$(wc -l < "$PUT_LOG")
    echo "put_repro.py log written: $PUT_LOG ($LINES lines)"
else
    echo "WARNING: put_repro.py did not produce log at $PUT_LOG"
fi

echo ""
echo "============================================================"
echo "Done. Log files:"
echo "  bypass_test  : $BYPASS_LOG"
echo "  bypass console: $SCRIPT_DIR/bypass_test_console.log"
echo "  put_repro    : $PUT_LOG"
echo "============================================================"
