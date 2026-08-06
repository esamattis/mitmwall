#!/bin/sh

set -eu

python3 -m unittest discover -s "$(dirname "$0")/tests/unit" -p "test_*.py"

if command -v uv >/dev/null 2>&1; then
    uv run basedpyright
    echo "basedpyright (uv): OK"
elif command -v basedpyright >/dev/null 2>&1; then
    basedpyright
    echo "basedpyright: OK"
else
    echo "test.sh: uv or basedpyright is required to run type checking" >&2
    exit 1
fi
