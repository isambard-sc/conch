<!--
SPDX-FileCopyrightText: © 2026 Ute Deittert <ute.deittert@bristol.ac.uk>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributing to Conch

Thanks for your interest in improving Conch! This guide covers how to set up a
development environment, build and test the project, and get your changes merged.
If you just want to *run* Conch, see the [README](./README.md) instead.

## Prerequisites

To build and run the unit tests you need:

- [Rust](https://rustup.rs) (stable toolchain) with `clippy` and `rustfmt`:
  ```shell
  rustup toolchain install stable --component=clippy,rustfmt
  ```

To build the container image and run the integration tests you additionally need:

- The MUSL target and tools (for a static binary):
  ```shell
  rustup target add x86_64-unknown-linux-musl
  sudo apt install musl-tools   # or your distro's equivalent
  ```
- [Podman](https://podman.io)
- [Helm](https://helm.sh)
- [Hurl](https://hurl.dev)
- `jq`, `curl` and `ssh-keygen`

## Getting the code

```shell
git clone https://github.com/isambard-sc/conch.git
cd conch
```

## Building

```shell
cargo build            # debug build
cargo build --release  # optimised build, as used for releases
```

The version string is derived from `git describe` at build time (see `build.rs`),
so building from a shallow clone may produce an unexpected version.

## Running checks locally

CI runs the following on every pull request. Please run them before pushing:

```shell
cargo fmt --check
cargo clippy
cargo test
```

Note that the crate's lints forbid `unsafe` code and deny `unwrap()`, `expect()`
and `dbg!()` outside of tests, so handle errors explicitly (e.g. with `anyhow`).

### Integration tests

The integration tests start a Keycloak instance and Conch in Podman, then
exercise the API with Hurl:

```shell
oci/build.sh                       # builds the binary and the conch:latest image
tests/integration/integration.sh
```

To run Conch in a container against the test Keycloak without running the test
suite (useful for manual debugging), use `tests/integration/run.sh`.

## Documentation

The user documentation lives in `docs/` and is published to
[conch.readthedocs.io](https://conch.readthedocs.io). To preview it locally:

```shell
python -m venv .venv
.venv/bin/pip install -r docs/requirements.txt
.venv/bin/sphinx-autobuild docs docs/_build/html
```

If you change the API or configuration format, please update `docs/api.rst` or
`docs/config.rst` (and the README examples) in the same pull request.

## Changelog

Every user-visible change needs an entry in the `Unreleased` section of
[CHANGELOG.md](./CHANGELOG.md), following [Keep a Changelog](https://keepachangelog.com).
CI checks the format with [python-kacl](https://pypi.org/project/python-kacl/):

```shell
pip install python-kacl
kacl-cli verify
```

## Licensing

Conch follows the [REUSE](https://reuse.software) specification. Every new file
needs an SPDX header (or an entry in `REUSE.toml` if it cannot hold a comment):

- Code: `MIT`
- Documentation and prose: `CC-BY-SA-4.0`
- Trivial config files: `CC0-1.0`

Check compliance with:

```shell
pip install reuse
reuse lint
```

## Submitting changes

1. Fork the repository (or clone it, if you have write access) and create a branch from `master`.
2. Make your change, with tests where practical.
3. Run the checks above and add a changelog entry.
4. Open a pull request describing what changed and why.

If you change anything under `.github/workflows/`, CI will also run
[actionlint](https://github.com/rhysd/actionlint) and [zizmor](https://github.com/zizmorcore/zizmor),
so pin any new actions to a commit SHA and keep permissions minimal.

## Releases

Releases are made by maintainers via GitHub Actions; see [RELEASE.md](./RELEASE.md).
