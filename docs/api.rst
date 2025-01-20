.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

HTTP API
========

Conch provides a HTTP API to perform signing requests.

.. http:get:: /sign

   Sign a public SSH key, using the provided JWT to authorise.

   **Example request**:

   .. sourcecode:: http

      GET /sign?public_key=ssh-ed25519%20AAAAC3NzaC1lZ<example-snipped> HTTP/1.1
      Host: example.com
      Accept: application/json
      Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cC<example snipped>

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
        "certificate": "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC<example snipped>",
        "platforms": {
          "batch.cluster1.example": {
            "alias": "cluster1.example",
            "hostname": "1.access.example.com",
            "proxy_jump": "bastion.example.com"
          },
          "batch.cluster2.example": {
            "alias": "cluster2.example",
            "hostname": "2.access.example.com",
            "proxy_jump": "bastion.example.com"
          }
        },
        "projects": {
          "project-a": [
            "batch.cluster1.example",
          ],
          "project-b": [
            "batch.cluster2.example"
          ]
        },
        "short_name": "test_person",
        "user": "test@example.com",
        "version": 2
      }

   :query string public_key: the SSH public key to sign

   :<header Authorization: an OIDC access token in JWT form. See :ref:`claims` for more information on the contents.

   :>json string certificate: the SSH certificate
   :>json Platforms platforms: the platforms the certificate can be used on. See :confval:`platforms` for the structure.
   :>json Project projects: the projects the user is part of. This is extracted from the `projects` :ref:`claim <claims>`.
   :>json string short_name: the short name of the user
   :>json string user: the email address of the user
   :>json integer version: the version of the response. Currently ``2``.

.. http:get:: /issuer

   .. deprecated:: 0.3

      Use :http:get:`/oidc` instead.

   Get the URL of the OIDC issuer.

   **Example request**:

   .. sourcecode:: http

      GET /issuer HTTP/1.1
      Host: example.com

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK

      https://keycloak.example.com/realms/example

.. http:get:: /oidc

   .. versionadded:: 0.3

   Get the details of the OIDC issuer and client information to use.

   **Example request**:

   .. sourcecode:: http

      GET /client_id HTTP/1.1
      Host: example.com

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {
        "issuer": "https://keycloak.example.com/realms/example",
        "client_id": "clifton",
        "version": 1
      }

   :>json string issuer: the URL of the OIDC issuer.
   :>json string client_id: the ID of the OIDC client to use when talking to the issuer.
   :>json integer version: the version of the response. Currently ``1``.

.. http:get:: /public_key

   .. versionadded:: 0.2

   Get the public part of the currently used signing key.

   **Example request**:

   .. sourcecode:: http

      GET /public_key HTTP/1.1
      Host: example.com

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK

      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsaKBqZPg<example snipped>

.. http:get:: /health

   .. versionadded:: 0.1.3

   Check the health of the service.

   **Example request**:

   .. sourcecode:: http

      GET /health HTTP/1.1
      Host: example.com

   **Example response**:

   .. sourcecode:: http

      HTTP/1.1 200 OK
      Content-Type: application/json

      {}

   :statuscode 200: Conch is running and working.
