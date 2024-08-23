# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
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
- Added a readiness probe to Kubernetes manifest.
- Allow setting the log format to JSON.

### Changed
- Run the service as a non-root user

## [0.1.2] - 2024-08-15
### Changed
- Port to new claims format and change certificate response to match. Now version 2.
- Filter out irrelevant platforms.

## [0.1.1] - 2024-08-13
### Added
- Add Kubernetes Service to Helm chart.
- Make logging level configurable, and default to `info`.
- Make SSH signing key secret name configurable.
- Remove `ports.hostPort` from `Deployment`.

### Fixed
- Correct `apiVersion` for `Deployment`.
- `volumeMounts.read-only` → `volumeMounts.readOnly`

## [0.1.0] - 2024-08-09
### Added
- Initial release

[0.1.5]: https://github.com/isambard-sc/conch/releases/tag/0.1.5
[0.1.4]: https://github.com/isambard-sc/conch/releases/tag/0.1.4
[0.1.3]: https://github.com/isambard-sc/conch/releases/tag/0.1.3
[0.1.2]: https://github.com/isambard-sc/conch/releases/tag/0.1.2
[0.1.1]: https://github.com/isambard-sc/conch/releases/tag/0.1.1
[0.1.0]: https://github.com/isambard-sc/conch/releases/tag/0.1.0
