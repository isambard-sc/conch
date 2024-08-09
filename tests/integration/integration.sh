#! /bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT
set -euo pipefail

# Run the integration tests in podman.

header() { echo "$(tput bold)${@}$(tput sgr0)" ; }

function on_exit {
    rm -rf tests/integration/temp
    rm -f conch.log keycloak.log
    podman pod logs conch-pod &> conch.log
    podman pod logs keycloak &> keycloak.log
    echo "Shutting down pod"
    podman pod rm --force --time=0 conch-pod || podman pod rm --force conch-pod
    podman pod rm --force --time=0 keycloak || podman pod rm --force keycloak
}

trap on_exit EXIT

function wait_for_url {
    echo "Testing $1..."
    printf 'GET %s\nHTTP 200' "$1" | hurl --retry "$2" > /dev/null;
    return 0
}

header "Starting container"
tests/integration/run.sh

header "Waiting server to be ready"
wait_for_url "http://localhost:3000" 30

header "Logging in as test user"
ISSUER=http://localhost:8080/realms/conch
TOKEN=$(curl --silent --show-error --data "username=test&password=test&grant_type=password&client_id=conch" ${ISSUER}/protocol/openid-connect/token | jq --raw-output '.access_token')
echo "Test user token: $TOKEN"

header "Generating SSH keys"
mkdir -p temp
rm -f tests/integration/temp/id_*
ssh-keygen -q -t ed25519 -N '' -f tests/integration/temp/id_ed25519
SSH_KEY_ED25519_PUB=$(cat tests/integration/temp/id_ed25519.pub)
ssh-keygen -q -t rsa -b 2048 -N '' -f tests/integration/temp/id_rsa_2048
SSH_KEY_RSA_2048_PUB=$(cat tests/integration/temp/id_rsa_2048.pub)
ssh-keygen -q -t rsa -b 3072 -N '' -f tests/integration/temp/id_rsa_3072
SSH_KEY_RSA_3072_PUB=$(cat tests/integration/temp/id_rsa_3072.pub)
ssh-keygen -q -t dsa -N '' -f tests/integration/temp/id_dsa
SSH_KEY_DSA_PUB=$(cat tests/integration/temp/id_dsa.pub)

header "Running Hurl tests"
hurl \
    --variable conch="http://localhost:3000" \
    --variable token="${TOKEN}" \
    --variable ssh_key_ed25519_pub="${SSH_KEY_ED25519_PUB}" \
    --variable ssh_key_rsa_2048_pub="${SSH_KEY_RSA_2048_PUB}" \
    --variable ssh_key_rsa_3072_pub="${SSH_KEY_RSA_3072_PUB}" \
    --variable ssh_key_dsa_pub="${SSH_KEY_DSA_PUB}" \
    --test tests/integration/*.hurl \
    --report-html results \
    --error-format long \
    --color
