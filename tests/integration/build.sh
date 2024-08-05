#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt,williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT
set -euo pipefail

# Build the project and create an OCI image containing it.

function artifact_path {
  echo "${1}" | jq --raw-output 'select(.reason == "compiler-artifact") | select(.target.name == "'"${2}"'") | .executable'
}

out=$(cargo build --message-format=json)
cp "$(artifact_path "${out}" "conch")" tests/integration/

cd tests/integration

echo "Building containers"
podman build . --tag=conch

rm conch
