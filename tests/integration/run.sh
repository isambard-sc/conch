#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

# This script can be used to run the service in a contianer, but
# outside of the test suite.

set -euo pipefail

header() { echo "$(tput bold)${@}$(tput sgr0)" ; }

cd tests/integration

header "Creating test signing key"
mkdir -p temp
rm -f temp/signing_key*
ssh-keygen -q -t ed25519 -f temp/signing_key -C '' -N ''
podman secret exists conch-signing-key-secret && podman secret rm conch-signing-key-secret
cat << EOF | podman secret create conch-signing-key-secret -
apiVersion: v1
kind: Secret
metadata:
  name: conch-signing-key-secret
data:
  key: $(base64 --wrap=0 temp/signing_key)
EOF
header "Templating conch helm chart"
rm -f conch-chart.yaml
helm template --values values.yaml ../../helm/conch > temp/conch-chart.yaml
header "Starting keycloak pod"
podman kube play --replace k8s.yml

header "Logging in to KeyCloak"
TOKEN=$(
  curl --retry 60 --retry-delay 2 --retry-all-errors --no-progress-meter \
    --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
    http://localhost:8080/realms/master/protocol/openid-connect/token |
  jq --raw-output '.access_token'
)
header "Creating conch KeyCloak realm"
curl -X POST http://localhost:8080/admin/realms \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data '{"realm":"conch", "enabled": true}'
header "Creating custom attributes"
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
        "multivalued": false
      },
      {"name": "username"},
      {"name": "email"}
    ]
  }
EOF
header "Creating client scope"
curl -X POST http://localhost:8080/admin/realms/conch/client-scopes \
  -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --fail-with-body -w "\n"\
  --data '{"id":"extra", "name":"extra", "protocol":"openid-connect"}'
header "Creating protocol mapper to include unix username attributes"
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
header "Creating protocol mapper to include projects attributes"
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
      "jsonType.label": "JSON",
      "multivalued": false
    }
  }
EOF
header "Creating conch OIDC client"
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
header "Creating test user"
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
      "projects": ["{\"proj1\": [\"ai.isambard\", \"3.isambard\"], \"proj2\": [\"ai.isambard\"]}"]
    }
  }
EOF
header "Getting user ID"
USERIDS=$(
  curl -X GET http://localhost:8080/admin/realms/conch/users \
    -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --no-progress-meter |
  jq --raw-output '.[].id'
)
header "Setting test user passwords"
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

header "Starting conch chart"
podman kube play --replace temp/conch-chart.yaml
