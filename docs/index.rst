.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Conch
=====

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   config
   api

Conch is an `SSH certificate`_ issuer which authenticates using OIDC access tokens.

It is intended to be used as a part of an interactive workflow where a real human is getting access to a system via SSH.

Flow
----

The general high-level flow for a client interating with Conch to get a signed certificate is:

.. mermaid::

   sequenceDiagram
      participant OIDC as OIDC issuer
      actor Client
      participant Conch

      Client->>OIDC: Authenticate
      OIDC->>Client: Access token (JWT)

      Client->>+Conch: /sign<br/>Passing the JWT
      Conch->>OIDC: Validate JWT
      note over Conch: Extract JWT claims and<br/>map to certificate principals

      Conch->>-Client: Signed certificate

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

.. _SSH certificate: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
