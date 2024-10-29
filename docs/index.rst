.. SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
   SPDX-License-Identifier: CC-BY-SA-4.0

Conch
=====

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   config

Conch is an `SSH certificate`_ issuer which authenticates using OIDC access tokens.

It is intended to be used as a part of an interactive workflow where a real human is getting access to a system via SSH.

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
.. _OpenID Provider Issuer discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
.. _SSH config Host: https://man.openbsd.org/ssh_config#Host
.. _TOML: https://toml.io
