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
kubectl create secret generic conch-signing-key-secret --from-file=key=ssh_signing_key
rm ssh_signing_key
```

then, you can create a `values.yaml` like:

```yaml
---
config:
  issuer: "https://keycloak.example.com/realms/example"
  platforms:
    service-one:
      alias: "s1.example"
      hostname: "s1.example.com"
      proxy_jump: "jump.example.com"
```

You should avoid making the `alias` a resolvable domain name as it will be used in SSH configs and works best if it forms its own namespace.

and install the chart with:

```sh
helm upgrade conch oci://ghcr.io/isambard-sc/charts/conch --version x.y.z --install --values values.yaml
```

### OCI image

Conch can be deployed as a container using e.g. Podman.

First, create the private SSH signing key:

```sh
ssh-keygen -q -t ed25519 -f ssh_signing_key -C '' -N ''
```

Then set up the config file:

```toml
signing_key_path = "/signing_key"

issuer = "https://keycloak.example.com/realms/example"

[platforms.service-one]
alias = "s1.example"
hostname = "s1.example.com"
proxy_jump = "jump.example.com"
```

and run the container, pointing it to those two files:

```sh
podman run \
  -v conch.toml:/conch.toml \
  -v ssh_signing_key:/signing_key \
  -e RUST_LOG=info \
  ghcr.io/isambard-sc/conch:0.1.4 --config=/conch.toml
```

### Binary

Conch can be run as a simple binary.
They can be downloaded from [releases].

Create the signing key and config file as above (editing the config file to point to the local location of the signing key).
You can then run it with:

```sh
env RUST_LOG=info conch --config=conch.toml
```

## OIDC

All the methods above require an OIDC issuer to be specified.
Any client communicating with Conch (e.g. [Clifton][clifton]) will need to provide a signed JWT which Conch will validate against the issuer.
This means that the issuer that the client uses must match the issuer configured in Conch.

## Name

The famous conch in William Golding's _Lord of the Flies_ was, according to [his daughter][shell], inspired by a shell in the Bristol Museum of Natural History.
Given that this tool is to give access to secure shells, it seemed a fitting reference.

[releases]: https://github.com/isambard-sc/conch/releases
[clifton]: https://github.com/isambard-sc/clifton/
[shell]: https://www.bristolmuseums.org.uk/stories/tales-from-natural-history-stores/

