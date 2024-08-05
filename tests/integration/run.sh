#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

# This script can be used to run the service in a contianer, but
# outside of the test suite.

set -euo pipefail

cd tests/integration

echo "Deleting existing pod"
podman pod rm --force --time=0 conch || true
echo "Creating new pod"
podman pod create --publish=3000:3000 --name conch
echo "Starting container"
podman container run --detach --pod=conch --env='RUST_LOG=debug' conch
