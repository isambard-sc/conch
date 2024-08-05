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
echo "Starting keycloak container"
podman container run --detach --pod=conch --name keycloak-c \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:25.0 \
  start-dev
echo "Logging in to KeyCloak"
n=0
until [ "$n" -ge 30 ]
do
  podman exec keycloak-c /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin && break
  n=$((n+1))
  echo "retrying..."
  sleep 2
done
echo "Creating conch KeyCloak realm"
podman exec keycloak-c /opt/keycloak/bin/kcadm.sh create realms -s realm=conch -s enabled=true
echo "Creating conch OIDC client"
podman exec -i keycloak-c /opt/keycloak/bin/kcadm.sh create clients -r conch -f - << EOF
{
  "clientId": "conch",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "TestClientSecretKEyGmXlLlC9z4V3dD",
  "redirectUris": [
    "http://localhost:3000/callback"
  ],
  "standardFlowEnabled": true,
  "protocol": "openid-connect",
  "fullScopeAllowed": true,
  "defaultClientScopes": [
    "web-origins",
    "acr",
    "profile",
    "roles",
    "basic",
    "email"
  ]
}
EOF
echo "Starting conch container"
podman container run --detach --pod=conch --env='RUST_LOG=debug' --name conch-c conch
