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

Version compatibility
---------------------

In order to make upgrading reliable and predictable, we define version compatibility explicitly.
Conch follows `SemVer`_ with the following clarifications:

- Adding a new, required configuration variable is not backwards compatible as it will require a change by the administrator.
- Adding a new, optional configuration variable is backwards compatible.
- Changing the meaning of a configuration variable is not backwards compatible.
- Removing or changing the value of a returned JSON member is not backwards compatible.
- Adding a new member to a returned JSON object is backwards compatible.

JSON responses will contain a ``version`` member which will be an integer which increments by 1 each time a backwards-incompatible change is made to it.

We commit, as far as we are able, to making upgrading Conch with a ``y`` or ``z`` version number change to be safe

While in pre-1.0, a ``y`` version change will denote a backwards-incompatible change and a ``z`` will denote a backwards-compatible release.

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

.. _SSH certificate: https://datatracker.ietf.org/doc/draft-miller-ssh-cert/
.. _SemVer: https://semver.org/spec/v2.0.0.html
