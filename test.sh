#!/bin/sh

set -eu


if command -v uvx >/dev/null 2>&1; then
    uvx ty check
fi

# The test suite exercises Linux-specific firewall and system integration.
case "$(uname -s)" in
    Linux)
        python3 "$(dirname "$0")/test.py"
        ;;
    *)
        echo "test.sh: Linux is required to run all tests" >&2
        exit 1
        ;;
esac

if ! command -v uvx >/dev/null 2>&1; then
    echo "test.sh: uvx is required to run type checking" >&2
    exit 1
fi
