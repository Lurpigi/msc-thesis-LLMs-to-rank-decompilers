#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="python3"
SCRIPT="$DIR/rulechef.py"
RULES_DIR="$DIR/rules"

if [ ! -f "$SCRIPT" ]; then
    echo "error: $SCRIPT not found" >&2
    exit 1
fi

if [ ! -d "$RULES_DIR" ]; then
    echo "error: $RULES_DIR not found" >&2
    exit 1
fi

for i in {1..7}; do
    IN="$RULES_DIR/$i.txt"
    OUT="$DIR/$i.txt"
    if [ ! -f "$IN" ]; then
        echo "warning: $IN not found, skipping" >&2
        continue
    fi
    echo "Running: $PY $SCRIPT $IN -> $OUT"
    "$PY" "$SCRIPT" "$IN" > "$OUT"
done