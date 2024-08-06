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

echo "Extracting OIDC client information"
cat << EOF > conch.toml
issuer = "http://0.0.0.0:8080/realms/conch"
signing_key_path = "/signing_key"
EOF

echo "Creating test signing key"
rm -f signing_key*
ssh-keygen -q -t ed25519 -f signing_key -C '' -N ''

echo "Building containers"
podman build . --tag=conch

echo "Cleaning up"
rm -f conch signing_key*
