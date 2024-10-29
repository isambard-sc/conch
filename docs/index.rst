.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Conch
=====

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Conch is an `SSH certificate`_ issuer which authenticates using OIDC access tokens.

It is intended to be used as a part of an interactive workflow where a real human is getting access to a system via SSH.

Installation
------------

Conch can be deployed in a few different way, but all require a private SSH signing key to be created:

.. code-block:: shell-session

   $ ssh-keygen -q -t ed25519 -f ssh_signing_key -C '' -N ''

Helm
~~~~

First, create the SSH signing key and put it in a ``Secret``:

.. code-block:: shell-session

   $ kubectl create secret generic conch-signing-key-secret --from-file=key=ssh_signing_key
   $ rm ssh_signing_key

then, you can create a ``values.yaml`` (see :ref:`config` for details) like:

.. code-block:: yaml

   ---
   config:
     issuer: "..."
     platforms: [...]
     mappers: [...]

Note that the Helm chart manages the config value :confval:`signing_key_path` for you by mounting the file as a read-only volume so you do not need to set it.

You can then install the chart with:

.. code-block:: shell-session

   $ helm upgrade conch oci://ghcr.io/isambard-sc/charts/conch --version x.y.z --install --values values.yaml

OCI image
~~~~~~~~~

Conch can be deployed as a container using e.g. Podman.

Set up a config file ``conch.toml`` as described in :ref:`config` and run the container, mounting both the config file and the signing key itself:

.. code-block:: shell-session

   $ podman run \
     -v conch.toml:/conch.toml \
     -v ssh_signing_key:/signing_key \
     -e RUST_LOG=info \
     ghcr.io/isambard-sc/conch:0.1.4 --config=/conch.toml

Binary
~~~~~~

Conch can be run as a simple binary.
They can be downloaded from `releases`_.

Create the config file as described in :ref:`config` (editing it to point to the local location of the signing key).
You can then run it with:

.. code-block:: shell-session

   $ env RUST_LOG=info conch --config=conch.toml

OIDC
----

All the methods above require an OIDC issuer to be specified.
Any client communicating with Conch (e.g. `Clifton`_) will need to provide an access token (in JWT format) which Conch will validate against the issuer.
This means that the issuer that the client uses must match the issuer configured in Conch.

Claims required
~~~~~~~~~~~~~~~

When requesting an SSH certificate from Conch, a user must authenticate themselves by passing a JSON Web Token.
Conch will validate this JWT by checking that is was signed by an :confval:`issuer` that you define.

There are three JWT claims that Conch requires in order to generate the response containing the signed certificate:

``email``
   This must be a string containing some unique identifier for the user.
   Usually this is the email address of the user.

``short_name``
   This must be a string containing a UNIX username-compatible name.

   If using the ``project_infra`` version 1 mapper, this will be combined with the :term:`project` names to create the principals in the certificate.

``projects``
   This must be a JSON object containing a string key for each :term:`project` name, with the value being a list of strings of the :term:`platform` names (see :confval:`platforms`) that the project is available on.
   For example, this could look like:

   .. code-block:: json

      {
         "project-a": [
            "batch.cluster1.example",
            "batch.cluster2.example"
         ],
         "project-b": [
            "batch.cluster2.example"
         ]
      }

.. _config:

Configuration
-------------

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

      A claim containing a single string should be placed verbatim into the principal list.

      .. code-block:: toml

         [[mappers]]
         single = "email"

   .. confval:: list

      A claim containing a JSON list of strings, each of which will be mapped directly into the principal list.

      .. code-block:: toml

         [[mappers]]
         list = "names"

   .. confval:: project_infra

      This will generate a list of principals of the form ``<short_name>.<project-name>``.
      The prefix ``<short_name>`` comes from a string claim ``short_name`` and the ``<project-name>`` comes from each of the project names defined in the ``projects`` claim.

      Currently the only valid value for ``project_infra`` is ``"v1"``.

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

Key management
--------------

Conch reads the signing key live on each signing request.
This means that if you replace the private key on disk, any future requests will use it.

Glossary
--------

.. glossary::

   Project
      A project is intended to describe a time-limited collection of users with access to a particular set of :term:`platform`.

   Platform
      A platform is a collection of resources.
      In the context of Conch, it is anything which can be accessed via SSH.
      For example it might be a specific batch cluster or a development environment.

   Mapper
      A configurable function which takes claims and creates principals in the SSH certificate.

.. _releases: https://github.com/isambard-sc/conch/releases
.. _Clifton: https://github.com/isambard-sc/clifton/
.. _SSH certificate: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
.. _OpenID Provider Issuer discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
.. _SSH config Host: https://man.openbsd.org/ssh_config#Host
.. _TOML: https://toml.io
