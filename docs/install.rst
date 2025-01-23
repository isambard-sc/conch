.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Installation
============

Conch can be deployed in a few different way, but all require a private SSH signing key to be created:

.. code-block:: shell-session

   $ ssh-keygen -q -t ed25519 -f ssh_signing_key -C '' -N ''

Conch reads the signing key live on each signing request.
This means that if you replace the private key on disk, any future requests will use it.

Helm
----

First, create the SSH signing key and put it in a ``Secret``:

.. code-block:: shell-session

   $ kubectl create secret generic conch-signing-key-secret --from-file=key=ssh_signing_key
   $ rm ssh_signing_key

then, you can create a ``values.yaml`` (see :doc:`config` for details) like:

.. code-block:: yaml

   ---
   config:
     issuer: "..."
     platforms: [...]
     mappers: [...]
     extensions: [...]

Note that the Helm chart manages the config value :confval:`signing_key_path` for you by mounting the file as a read-only volume so you do not need to set it.

You can then install the chart with:

.. code-block:: shell-session

   $ helm upgrade conch oci://ghcr.io/isambard-sc/charts/conch --version x.y.z --install --values values.yaml

OCI image
---------

Conch can be deployed as a container using e.g. Podman.

Set up a config file ``conch.toml`` as described in :doc:`config` and run the container, mounting both the config file and the signing key itself:

.. code-block:: shell-session

   $ podman run \
     -v conch.toml:/conch.toml \
     -v ssh_signing_key:/signing_key \
     -e RUST_LOG=info \
     ghcr.io/isambard-sc/conch:0.1.4 --config=/conch.toml

Binary
------

Conch can be run as a simple binary.
They can be downloaded from `releases`_.

Create the config file as described in :doc:`config` (editing it to point to the local location of the signing key).
You can then run it with:

.. code-block:: shell-session

   $ env RUST_LOG=info conch --config=conch.toml

OIDC
----

All the methods above require an OIDC issuer to be specified.
Any client communicating with Conch (e.g. `Clifton`_) will need to provide an access token (in JWT format) which Conch will validate against the issuer.
This means that the issuer that the client uses must match the issuer configured in Conch.

.. _claims:

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
   This must be a JSON object containing a string key for each :term:`project` name,
   with the value being a list of objects containing a ``name`` member giving the project name and a ``resources`` member giving the :term:`platform`\ s  (see :confval:`platforms`) that the project is available on.
   For example, this could look like:

   .. code-block:: json

      {
         "project-a": {
            "name": "Project A",
            "resources": [
               {
                  "name": "batch.cluster1.example",
                  "username": "user.proj-a"
               },
               {
                  "name": "batch.cluster2.example",
                  "username": "user.proj-a"
               }
            ]
         },
         "project-b": {
            "name": "Project B",
            "resources": [
               {   
                  "name": "batch.cluster2.example",
                  "username": "user.proj-b"
               }
            ]
         }
      }

.. _releases: https://github.com/isambard-sc/conch/releases
.. _Clifton: https://github.com/isambard-sc/clifton/
