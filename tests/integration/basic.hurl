# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

GET {{conch}}
HTTP 200

GET {{conch}}/issuer
HTTP 200
[Captures]
issuer: body
[Asserts]
body == "http://localhost:8080/realms/conch"

POST {{issuer}}/protocol/openid-connect/token
[FormParams]
username: test
password: test
grant_type: password
client_id: conch
[Options]
output: -
HTTP 200
[Captures]
test1_token: jsonpath "$.access_token"

POST {{issuer}}/protocol/openid-connect/token
[FormParams]
username: test2
password: test
grant_type: password
client_id: conch
HTTP 200
[Captures]
test2_token: jsonpath "$.access_token"

GET {{conch}}/sign
{}
HTTP 500

GET {{conch}}/sign
Authorization: Bearer {{ test1_token }}
[QueryStringParams]
public_key: {{ ssh_key_ed25519_pub }}
HTTP 200
[Asserts]
jsonpath "$.certificate" exists
jsonpath "$.projects['proj1']" includes "ai.example"
jsonpath "$.projects['proj1']" includes "3.example"
jsonpath "$.projects['proj2']" includes "ai.example"
jsonpath "$.projects['proj2']" not includes "3.example"
jsonpath "$.projects['proj2']" not includes "missing.example"
jsonpath "$.user" == "test@example.com"
jsonpath "$.version" == 2

GET {{conch}}/sign
Authorization: Bearer {{ test1_token }}
[QueryStringParams]
public_key: {{ ssh_key_rsa_3072_pub }}
HTTP 200
[Asserts]
jsonpath "$.certificate" exists

GET {{conch}}/sign
Authorization: Bearer {{ test1_token }}
[QueryStringParams]
public_key: {{ ssh_key_rsa_2048_pub }}
HTTP 500
[Asserts]
jsonpath "$.message" contains "RSA keys must be at least 3072 bits long"

GET {{conch}}/sign
Authorization: Bearer {{ test1_token }}
[QueryStringParams]
public_key: {{ ssh_key_dsa_pub }}
HTTP 500
[Asserts]
jsonpath "$.message" contains "DSA keys are not supported"

GET {{conch}}/sign
Authorization: Bearer {{ test2_token }}
[QueryStringParams]
public_key: {{ ssh_key_ed25519_pub }}
HTTP 500
[Asserts]
jsonpath "$.message" contains "No valid pricipals found after filtering"
