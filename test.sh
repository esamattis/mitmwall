#!/bin/sh

set -eu

python3 -m unittest discover -s "$(dirname "$0")/tests" -p "test_*.py"

if command -v basedpyright >/dev/null 2>&1; then
    basedpyright
    echo "basedpyright: OK"
else
    echo "test.sh: basedpyright is required to run type checking" >&2
    exit 1
fi
