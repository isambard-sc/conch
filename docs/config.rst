.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Configuration
=============

The native configuration format for Conch is a `TOML`_ file, passed as a command-line argument ``--config``.

If you are installing Conch via Helm with a ``values.yaml`` then these settings can be set under the ``config`` key, e.g.:

.. code-block:: yaml

   config:
     issuer: "https://example.com"

All the examples below show the syntax for both.

.. confval:: issuer
   :type: String (URL)

   This must be set as a string containing the URL of the OIDC issuer.
   It should be the path that contains the ``.well-known/openid-configuration`` location.
   For example, this could be set to ``"https://keycloak.example.com/realms/example"`` (such that ``https://keycloak.example.com/realms/example/.well-known/openid-configuration`` exists).
   The issuer must support `OpenID Provider Issuer discovery`_.

.. confval:: client_id
   :type: String

   The OIDC client ID that is configured at :confval:`issuer`.
   For example, it could be set to ``"clifton"``.

.. confval:: signing_key_path
   :type: String (path)

   This must be set to the path on disk where the private SSH key is stored.

.. confval:: resources
   :type: Table

   The name of the table should be a string of the name of the :term:`resource`.
   It must contain the following keys:

   .. confval:: alias

      a short string which can be used as an `SSH config Host`_ name.
      You should avoid making the ``alias`` a resolvable domain name as it works best if it forms its own namespace.

   .. confval:: hostname

      a string containing the real hostname of the resource to SSH into.

   .. confval:: proxy_jump

      an optional string containing the hostname to be used by `ProxyJump`.

   For example, it might look like:

   .. tabs::

      .. group-tab:: ``config.toml``

         .. code-block:: toml

            [resources."batch.cluster1.example"]
            alias = "cluster1.example"
            hostname = "1.access.example.com"
            proxy_jump = "bastion.example.com"

            [resources."batch.cluster2.example"]
            alias = "cluster2.example"
            hostname = "2.access.example.com"
            proxy_jump = "bastion.example.com"

      .. group-tab:: ``values.yaml``

         .. code-block:: yaml

            resources:
              batch.cluster1.example:
                alias: "cluster1.example"
                hostname: "1.access.example.com"
                proxy_jump: "bastion.example.com"
              batch.cluster2.example:
                alias: "cluster2.example"
                hostname: "2.access.example.com"
                proxy_jump: "bastion.example.com"

.. confval:: mapper
   :type: Table

   This must be set to the identity :term:`mapper` to apply.
   It configures which claims (or combinations thereof) should be put into the certificate principals and returned as an association.
   The available options are:

   .. confval:: single
      :type: String

      A claim containing a single string which is common to all resources and should be placed verbatim into the principal list.

      It will set the ``associations`` return member of the :http:get:`/sign` endpoint to a mapping of resource to username.

      .. tabs::

         .. group-tab:: ``config.toml``

            .. code-block:: toml

               [mapper]
               single = "email"

         .. group-tab:: ``values.yaml``

            .. code-block:: yaml

               mapper:
                 single: "email"

   .. confval:: per_resource
      :type: String

      Set a username per resource.

      Set this to the name of the claim that contains a JSON object with keys matching the resource names, and values being a JSON object with a single key, ``username`` with the value being the username on that resource.
      For example, a claim that looks like:

      .. code-block:: json
         :caption: user claims

         {
           //...
           "usernames": {
             "batch.cluster1.example": {
               "username": "foo"
             },
             "batch.cluster2.example": {
               "username": "bar"
             }
           }
           //...
         }

      would mean that the user has the username ``foo`` on ``batch.cluster1.example`` and ``bar`` on ``batch.cluster2.example`` and would be referenced in the config like:

      .. tabs::

         .. group-tab:: ``config.toml``

            .. code-block:: toml

               [mapper]
               per_resource = "usernames"

         .. group-tab:: ``values.yaml``

            .. code-block:: yaml

               mapper:
                  per_resource: "usernames"

      It will set the ``associations`` return member of the :http:get:`/sign` endpoint to the value of that claim.

   .. confval:: project_infra
      :type: String

      This allows for a separate username for each resource and project combination.

      ``"v1"``
         Use the ``projects`` claim as the basis for the principals.
         There should be a claim called ``projects`` which must be a JSON object containing a string key for each :term:`project` ID,
         with the value being an object with a ``name`` member giving the human-readable project name and a ``resources`` member giving the :term:`resource`\ s  (see :confval:`resources`) that the project is available on along with the corresponding ``username``.

         For example, this could look like:

         .. code-block:: json

            {
              "project-a": {
                "name": "Project A",
                  "resources": {
                    "batch.cluster1.example": {
                      "username": "user.proj-a"
                    },
                    "batch.cluster2.example": {
                      "username": "user.proj-a"
                    }
                 }
              },
              "project-b": {
                "name": "Project B",
                  "resources": {
                    "batch.cluster2.example": {
                      "username": "user.proj-b"
                    }
                 }
              }
            }

         It will set the ``associations`` return member of the :http:get:`/sign` endpoint to the value of the ``projects`` claim.

      .. tabs::

         .. group-tab:: ``config.toml``

            .. code-block:: toml

               [mapper]
               project_infra = "v1"

         .. group-tab:: ``values.yaml``

            .. code-block:: yaml

               mapper:
                 project_infra: "v1"

.. confval:: extensions
   :type: Array of Strings
   :default: []

   A list of the SSH certificate extensions that should be enabled on any generated certificates.
   For example:

   .. code-block:: toml

      extensions = ["permit-pty", "permit-agent-forwarding"]

.. _OpenID Provider Issuer discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
.. _SSH config Host: https://man.openbsd.org/ssh_config#Host
.. _TOML: https://toml.io
