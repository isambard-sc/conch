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
podman pod create --publish=3000:3000 --publish=8080:8080 --name conch

echo "Starting keycloak container"
podman container run --detach --pod=conch --name keycloak-c \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:25.0 \
  start-dev --http-port=8080
echo "Logging in to KeyCloak"
TOKEN=$(
  curl --retry 60 --retry-delay 2 --retry-all-errors --no-progress-meter \
    --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
    http://localhost:8080/realms/master/protocol/openid-connect/token |
  jq --raw-output '.access_token'
)
echo "Creating conch KeyCloak realm"
curl -X POST http://localhost:8080/admin/realms \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data '{"realm":"conch", "enabled": true}'
echo "Creating custom attributes"
curl -X PUT http://localhost:8080/admin/realms/conch/users/profile \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data @- << EOF
  {
    "attributes": [
      {
        "name": "unix_username",
        "permissions": {"view":["admin","user"],"edit":["admin"]},
        "multivalued": false
      },
      {
        "name": "projects",
        "permissions": {"view":["admin","user"],"edit":["admin"]},
        "multivalued": true
      },
      {"name": "username"},
      {"name": "email"}
    ]
  }
EOF
echo "Creating client scope"
curl -X POST http://localhost:8080/admin/realms/conch/client-scopes \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data '{"id":"extra", "name":"extra", "protocol":"openid-connect"}'
echo "Creating protocol mapper to include unix username attributes"
curl -X POST http://localhost:8080/admin/realms/conch/client-scopes/extra/protocol-mappers/models \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data @- << EOF
  {
    "name":"unix_username",
    "protocol":"openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
      "user.attribute": "unix_username",
      "claim.name": "unix_username",
      "id.token.claim": true,
      "access.token.claim": true,
      "jsonType.label": "String"
    }
  }
EOF
echo "Creating protocol mapper to include projects attributes"
curl -X POST http://localhost:8080/admin/realms/conch/client-scopes/extra/protocol-mappers/models \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data @- << EOF
  {
    "name":"projects",
    "protocol":"openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "config": {
      "user.attribute": "projects",
      "claim.name": "projects",
      "id.token.claim": true,
      "access.token.claim": true,
      "jsonType.label": "String",
      "multivalued": true
    }
  }
EOF
echo "Creating conch OIDC client"
curl -X POST http://localhost:8080/admin/realms/conch/clients \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data @- << EOF
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
      "email",
      "extra"
    ]
  }
EOF
echo "Creating test user"
curl -X POST http://localhost:8080/admin/realms/conch/users \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n" \
  --data @- << EOF
  {
    "username": "test",
    "enabled": true,
    "email": "test@example.com",
    "emailVerified": true,
    "attributes": {
      "unix_username": ["test_person"],
      "projects": ["proj1", "proj2"]
    }
  }
EOF
echo "Getting user ID"
USERIDS=$(
  curl -X GET http://localhost:8080/admin/realms/conch/users \
    -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --no-progress-meter |
  jq --raw-output '.[].id'
)
echo "Setting test user passwords"
for USERID in ${USERIDS}; do
  curl -X PUT http://localhost:8080/admin/realms/conch/users/${USERID}/reset-password \
    -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n" \
    --data @- << EOF
    {
      "type": "password",
      "temporary": false,
      "value": "test"
    }
EOF
done

echo "Creating test signing key"
mkdir -p temp
rm -f temp/signing_key*
ssh-keygen -q -t ed25519 -f temp/signing_key -C '' -N ''
echo "Starting conch container"
podman container run --detach --pod=conch \
  --env='RUST_LOG=debug' \
  --env=CONCH_ISSUER="http://0.0.0.0:8080/realms/conch" \
  --env=CONCH_SIGNING_KEY_PATH="/signing_key" \
  --volume="./temp/signing_key":"/signing_key":ro \
  --name conch-c \
  conch --port 3000
