#!/bin/sh

set -eu

# The test suite exercises Linux-specific firewall and system integration.
if [ "$(uname -s)" != "Linux" ]; then
    echo "integration_tests.sh: Linux is required to run all tests" >&2
    exit 1
fi

sudo ../dev-install.sh

python3 "$(dirname "$0")/integration_tests.py"
