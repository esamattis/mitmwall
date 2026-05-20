#!/bin/sh

set -eu

# The test suite exercises Linux-specific firewall and system integration.
case "$(uname -s)" in
    Linux)
        ;;
    *)
        echo "test.sh: Linux is required" >&2
        exit 1
        ;;
esac

if command -v uvx >/dev/null 2>&1; then
    uvx ty check
fi

python3 "$(dirname "$0")/test.py"

if ! command -v uvx >/dev/null 2>&1; then
    echo "test.sh: uvx is required" >&2
    exit 1
fi
