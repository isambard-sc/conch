<!--
SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Making a release

Releases are completely automated by GitHub Actions:
1. Make sure the [changelog](./CHANGELOG.md) is up to date.
   A release cannot be made if there is nothing in the changelog in the `Unreleased` section.
2. Go the the [Release](https://github.com/isambard-sc/conch/actions/workflows/release.yml) workflow page.
3. Click "Run workflow" in the top right.
4. Make sure the `master` branch is selected.
5. In the box below, type `patch`, `minor` or `major`, depending on the [SemVer level](https://semver.org) of release to make.
6. Press the "Run workflow" button.

This will kick off a series of chained workflows, culminating in a new release appearing on the [Releases page](https://github.com/isambard-sc/conch/releases) and images and Helm charts added to the registry.

## Maintenance releases

If `master` contains breaking changes that are not ready to release,
a patch release can be made from a `release/<major>.<minor>` branch instead:

1. If the branch does not already exist, create it from the last commit on `master`
   that is compatible with the version being maintained, and push it.
   For example, `release/0.3` for the 0.3.x series.
2. Cherry-pick the fixes to include (e.g. Dependabot updates) onto the branch.
   Never merge `master` into a release branch, as that would bring in the breaking changes.
3. Update the changelog on the branch, as above.
4. Run the Release workflow as above, but select the release branch instead of `master`,
   and type `patch`.
5. Merge the release branch back into `master`,
   so that `master` has the release's changelog section and version history.

The branch can be kept for further patch releases in the same series,
and deleted once that series is no longer supported.
