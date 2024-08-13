<!--
SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Conch SSH CA

Conch is an SSH CA for use in AIRR sites.

## Installation

### Helm

First, create the SSH signing key and put it in a `Secret`:

```sh
ssh-keygen -q -t ed25519 -f ssh_signing_key -C '' -N ''
kubectl create secret generic conch-signing-key-secret --from-file=private=ssh_signing_key
rm ssh_signing_key
```

then, you can create a `values.yaml` like:

```yaml
---
config:
  issuer: "https://keycloak.example.com/realms/example"
  services:
    service-one:
      hostname: "s1.example.com"
      proxy_jump: "jump.example.com"
```

and install the chart with:

```sh
helm upgrade conch oci://ghcr.io/isambard-sc/charts/conch --version x.y.z --install --values values.yaml
```

## Name

The famous conch in William Golding's _Lord of the Flies_ was, according to [his daughter][shell], inspired by a shell in the Bristol Museum of Natural History.
Given that this tool is to give access to secure shells, it seemed a fitting reference.

[shell]: https://www.bristolmuseums.org.uk/stories/tales-from-natural-history-stores/

