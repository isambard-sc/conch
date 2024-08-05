#! /bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT
set -euo pipefail

# Run the integration tests in podman.

function on_exit {
    rm -f conch.log
    podman pod logs conch > conch.log
    echo "Shutting down pod"
    podman pod rm --force --time=0 conch || podman pod rm --force conch
}

trap on_exit EXIT

function wait_for_url {
    echo "Testing $1..."
    printf 'GET %s\nHTTP 200' "$1" | hurl --retry "$2" > /dev/null;
    return 0
}

echo "Starting container"
tests/integration/run.sh

echo "Waiting server to be ready"
wait_for_url "http://0.0.0.0:3000" 60

echo "Running Hurl tests"
hurl \
    --variable conch="http://0.0.0.0:3000" \
    --test tests/integration/*.hurl \
    --report-html results \
    --error-format long \
    --color

