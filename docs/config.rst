.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Configuration
=============

The native configuration format for Conch is a `TOML`_ file, passed as a command-line argument ``--config``.

.. confval:: issuer
   :type: String (URL)

   This must be set as a string containing the URL of the OIDC issuer.
   For example, this could be set to ``https://keycloak.example.com/realms/example``.
   The issuer must support `OpenID Provider Issuer discovery`_.

.. confval:: signing_key_path
   :type: String (path)

   This must be set to the path on disk where the private SSH key is stored.

.. confval:: platforms
   :type: Table

   The name of the table should be a string of the name of the :term:`platform`.
   It must contain the following keys:

   .. confval:: alias

      a short string which can be used as an `SSH config Host`_ name.
      You should avoid making the ``alias`` a resolvable domain name as it works best if it forms its own namespace.

   .. confval:: hostname

      a string containing the real hostname of the platform to SSH into.

   .. confval:: proxy_jump

      a string containing the hostname to be used by `ProxyJump`.

   For example, it might look like:

   .. code-block:: toml
      :caption: ``config.toml``

      [platforms."batch.cluster1.example"]
      alias = "cluster1.example"
      hostname = "1.access.example.com"
      proxy_jump = "bastion.example.com"

      [platforms."batch.cluster2.example"]
      alias = "cluster2.example"
      hostname = "2.access.example.com"
      proxy_jump = "bastion.example.com"

   or, if configuring Conch via Helm, in YAML form:

   .. code-block:: yaml
      :caption: ``values.yaml``

      platforms:
        batch.cluster1.example:
          alias: "cluster1.example"
          hostname: "1.access.example.com"
          proxy_jump: "bastion.example.com"
        batch.cluster2.example:
          alias: "cluster2.example"
          hostname: "2.access.example.com"
          proxy_jump: "bastion.example.com"

.. confval:: mappers
   :type: Array of Tables

   This must be set to a list containing the identity :term:`mapper`\ s to apply.
   Each of these configure which claims (or combinations thereof) should be put into the certificate principals.
   The available options are:

   .. confval:: single
      :type: String

      A claim containing a single string should be placed verbatim into the principal list.

      .. code-block:: toml

         [[mappers]]
         single = "email"

   .. confval:: list
      :type: String

      A claim containing a JSON list of strings, each of which will be mapped directly into the principal list.

      .. code-block:: toml

         [[mappers]]
         list = "names"

   .. confval:: project_infra
      :type: String

      This will generate a principal for each of the projects passed in.

      ``"v1"``
         Create principals of the form ``<short_name>.<project-name>``.
         The prefix ``<short_name>`` comes from a string claim ``short_name`` and the ``<project-name>`` comes from each of the project names defined in the ``projects`` claim.

      .. code-block:: toml

         [[mappers]]
         project_infra = "v1"

   You can set as many mappers as you like, just repeat the table:

   .. code-block:: toml
      :caption: ``config.toml``

      [[mappers]]
      single = "email"

      [[mappers]]
      single = "short_name"

      [[mappers]]
      list = "names"

   Or, if configuring Conch via Helm, the YAML would look like:

   .. code-block:: yaml
      :caption: ``values.yaml``

      mappers:
        - single: "email"
        - single: "short_name"
        - list: "names"

