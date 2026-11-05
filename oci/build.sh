#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT
set -euo pipefail

# Build the project and create an OCI image containing it.

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "${repo_root}"

profile=debug
for arg in "$@"; do
  case "${arg}" in
    --release) profile=release ;;
    *)
      echo "Unsupported build argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

case "$(podman info --format '{{.Host.Arch}}')" in
  amd64) rust_target=x86_64-unknown-linux-musl ;;
  arm64) rust_target=aarch64-unknown-linux-musl ;;
  *)
    echo "Unsupported Podman architecture: $(podman info --format '{{.Host.Arch}}')" >&2
    exit 1
    ;;
esac

podman build --file oci/Containerfile \
  --build-arg "CARGO_PROFILE=${profile}" \
  --build-arg "RUST_TARGET=${rust_target}" \
  --tag=conch:latest \
  --annotation="org.opencontainers.image.source=https://github.com/isambard-sc/conch" \
  --annotation="org.opencontainers.image.description=Conch SSH CA" \
  --annotation="org.opencontainers.image.licenses=MIT" \
  .

version=$(podman run --rm conch:latest --version | tail -n1 | cut -d' ' -f 2)
podman tag conch:latest conch:"${version}"
image_id=$(podman image inspect --format '{{.Id}}' conch:latest)
echo "Built conch image:" 1>&2
echo "${image_id}"
