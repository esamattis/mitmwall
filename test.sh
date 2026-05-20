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

exec python3 "$(dirname "$0")/test.py"
