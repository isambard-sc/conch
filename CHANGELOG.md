# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Now prints the user agent to the log.
- Set the certificate serial number to a random number. The number should not be absolutely relied upon to be unique.

## [0.3.1] - 2025-02-03
### Added
- Add internal flag to strip trailing component from dotted-path project IDs.

## [0.3.0] - 2025-01-30
### Added
- Add an `/oidc` endpoint to get the OIDC information to use.
- Add an `extensions` configuration option to chose the SSH extensions to enable.

### Changed
- Change the format of the `projects` claim required from the OIDC provder.

## [0.2.0] - 2024-11-05
### Changed
- Make the claim→principal mapping configurable.
  There is no longer any default mapper so no principals will be set unless you set one in the config.

### Added
- Add a `/public_key` endpoint to retrieve the currently-used public key

## [0.1.9] - 2024-09-18
### Fixed
- Raise error if the user's short name is not set.

## [0.1.8] - 2024-09-10
### Changed
- [OCI] Build Conch with MUSL and base the image on a static distroless image. This reduces attack surface and reduces image size by 66%.

## [0.1.7] - 2024-09-09
### Changed
- [helm] Only trigger reinstall if actual data in ConfigMap changes.

## [0.1.6] - 2024-09-09
### Changed
- Keep the platform name intact and return the alias.

## [0.1.5] - 2024-08-23
### Added
- Make the proxy_jump optional.

### Changed
- [helm] Restart the pod only if the hash of the config has changed.

## [0.1.4] - 2024-08-20
### Fixed
- Principals are based on project, not platform.

## [0.1.3] - 2024-08-20
### Added
- Add a health check endpoint.
- Allow setting the log format to JSON.
- [helm] Added a readiness probe to Kubernetes manifest.

### Changed
- [helm] Run the service as a non-root user

## [0.1.2] - 2024-08-15
### Changed
- Port to new claims format and change certificate response to match. Now version 2.
- Filter out irrelevant platforms.

## [0.1.1] - 2024-08-13
### Added
- Make logging level configurable, and default to `info`.
- Make SSH signing key secret name configurable.
- [helm] Add Kubernetes Service to Helm chart.
- [helm] Remove `ports.hostPort` from `Deployment`.

### Fixed
- [helm] Correct `apiVersion` for `Deployment`.
- [helm] `volumeMounts.read-only` → `volumeMounts.readOnly`

## [0.1.0] - 2024-08-09
### Added
- Initial release

[0.3.1]: https://github.com/isambard-sc/conch/releases/tag/0.3.1
[0.3.0]: https://github.com/isambard-sc/conch/releases/tag/0.3.0
[0.2.0]: https://github.com/isambard-sc/conch/releases/tag/0.2.0
[0.1.9]: https://github.com/isambard-sc/conch/releases/tag/0.1.9
[0.1.8]: https://github.com/isambard-sc/conch/releases/tag/0.1.8
[0.1.7]: https://github.com/isambard-sc/conch/releases/tag/0.1.7
[0.1.6]: https://github.com/isambard-sc/conch/releases/tag/0.1.6
[0.1.5]: https://github.com/isambard-sc/conch/releases/tag/0.1.5
[0.1.4]: https://github.com/isambard-sc/conch/releases/tag/0.1.4
[0.1.3]: https://github.com/isambard-sc/conch/releases/tag/0.1.3
[0.1.2]: https://github.com/isambard-sc/conch/releases/tag/0.1.2
[0.1.1]: https://github.com/isambard-sc/conch/releases/tag/0.1.1
[0.1.0]: https://github.com/isambard-sc/conch/releases/tag/0.1.0
