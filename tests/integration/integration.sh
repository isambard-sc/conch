#! /bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT
set -euo pipefail

# Run the integration tests in podman.

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "${repo_root}"
mkdir -p results

network="conch-integration-${$}"
export CONCH_INTEGRATION_NETWORK="${network}"
hurl_image=ghcr.io/orange-opensource/hurl:8.0.0

header() { echo "$(tput bold)${@}$(tput sgr0)" ; }

function on_exit {
    rm -rf tests/integration/temp
    podman logs conch-pod-conch &> conch.log || true
    podman logs keycloak-keycloak &> keycloak.log || true
    echo "Shutting down pod"
    podman pod rm --force --time=0 conch-pod || true
    podman pod rm --force --time=0 keycloak || true
    podman network rm "${network}" || true
}

trap on_exit EXIT

function wait_for_url {
    echo "Testing $1..."
    printf 'GET %s\nHTTP 200' "$1" | hurl_in_podman --retry "$2" > /dev/null
    return 0
}

function hurl_in_podman {
    podman run --rm -i \
        --network="${network}" \
        --volume "${repo_root}/tests/integration:/tests:ro" \
        --volume "${repo_root}/results:/results" \
        --entrypoint hurl "${hurl_image}" "$@"
}

header "Starting container"
tests/integration/run.sh

header "Waiting server to be ready"
wait_for_url "http://conch-pod:3000" 30

header "Generating SSH keys"
mkdir -p temp
rm -f tests/integration/temp/id_*
ssh-keygen -q -t ed25519 -N '' -f tests/integration/temp/id_ed25519
SSH_KEY_ED25519_PUB=$(cat tests/integration/temp/id_ed25519.pub)
ssh-keygen -q -t rsa -b 2048 -N '' -f tests/integration/temp/id_rsa_2048
SSH_KEY_RSA_2048_PUB=$(cat tests/integration/temp/id_rsa_2048.pub)
ssh-keygen -q -t rsa -b 3072 -N '' -f tests/integration/temp/id_rsa_3072
SSH_KEY_RSA_3072_PUB=$(cat tests/integration/temp/id_rsa_3072.pub)

header "Running Hurl tests"
hurl_files=()
for hurl_file in tests/integration/*.hurl; do
    hurl_files+=("/tests/$(basename "${hurl_file}")")
done
hurl_in_podman \
    "${hurl_files[@]}" \
    --variable conch="http://conch-pod:3000" \
    --variable ssh_key_ed25519_pub="${SSH_KEY_ED25519_PUB}" \
    --variable ssh_key_rsa_2048_pub="${SSH_KEY_RSA_2048_PUB}" \
    --variable ssh_key_rsa_3072_pub="${SSH_KEY_RSA_3072_PUB}" \
    --test \
    --report-html /results \
    --error-format long \
    --color
