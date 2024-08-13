# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

GET {{conch}}
HTTP 200

GET {{conch}}/sign
{}
HTTP 500

GET {{conch}}/sign
Authorization: Bearer {{ token }}
[QueryStringParams]
public_key: {{ ssh_key_ed25519_pub }}
HTTP 200
[Asserts]
jsonpath "$.certificate" exists
jsonpath "$.projects['proj1']" includes "ai.isambard"
jsonpath "$.projects['proj1']" includes "3.isambard"
jsonpath "$.projects['proj2']" includes "ai.isambard"
jsonpath "$.projects['proj2']" not includes "3.isambard"
jsonpath "$.user" == "test@example.com"
jsonpath "$.version" == 2

GET {{conch}}/sign
Authorization: Bearer {{ token }}
[QueryStringParams]
public_key: {{ ssh_key_rsa_3072_pub }}
HTTP 200
[Asserts]
jsonpath "$.certificate" exists

GET {{conch}}/sign
Authorization: Bearer {{ token }}
[QueryStringParams]
public_key: {{ ssh_key_rsa_2048_pub }}
HTTP 500
[Asserts]
jsonpath "$.message" contains "RSA keys must be at least 3072 bits long"

GET {{conch}}/sign
Authorization: Bearer {{ token }}
[QueryStringParams]
public_key: {{ ssh_key_dsa_pub }}
HTTP 500
[Asserts]
jsonpath "$.message" contains "DSA keys are not supported"
