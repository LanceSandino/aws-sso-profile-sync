# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes describe user-visible changes, newest first.

## [2.1.1] — 2026-10-24

Security release. Upgrade from any earlier version; the CLI's commands, profile names and configuration behavior are unchanged.

### Fixed

- Release binaries are built with Go 1.27.3. 2.1.0 was built with Go 1.27.1, and govulncheck reports nine Go standard-library vulnerabilities in that toolchain as reachable from the CLI:
  - GO-2026-6809 (CVE-2026-111943): `crypto/x509` accepted known compromised intermediate certificates.
  - GO-2026-6607 (CVE-2026-97031): `crypto/tls` accepted malformed ECH outer extension references.
  - GO-2026-6605 (CVE-2026-56866): HTTP/1 client connection desynchronization after a rejected CONNECT.
  - GO-2026-6610 (CVE-2026-78660): the HTTP/2 transport accepted malformed framing-related headers.
  - GO-2026-6611 (CVE-2026-78669): excessive CPU use from repeated HTTP/2 initial window changes.
  - GO-2026-6603 (CVE-2026-78659), GO-2026-6613 (CVE-2026-94439), GO-2026-6617 (CVE-2026-97032) and GO-2026-6608 (CVE-2026-94440): `net/http` and `net/textproto` fixes from Go 1.27.2.
- Development and integration-test dependencies are updated, including `golang.org/x/crypto` 0.58.0 (GO-2026-6354 and GO-2026-6355 in `x/crypto/ssh`, test tooling only) and Testcontainers-Go 0.44.0.

### Improved

- All Go modules are updated to their latest releases, including the AWS SDK for Go v2 (`credentials` 1.20.10, `sso` 1.38.5, `ssooidc` 1.43.5) and `golang.org/x/sys` 0.49.0. Their license texts are unchanged.
- Go source builds now require Go 1.26 or newer, the oldest supported Go release series; current dependencies no longer support Go 1.25.
- Validation runs govulncheck on shipping and integration code, a scheduled workflow repeats it weekly, and Dependabot proposes Go module and GitHub Actions updates.
- Patch and minor releases are now accepted by the automated release validation: native build, race, coverage, distribution and installation tests on all four targets, plus Floci emulator acceptance with synthetic data. Real IAM Identity Center and AWS CLI acceptance remains required for major releases. 2.1.1 was accepted this way; real acceptance last passed for 2.1.0. Release archive metadata records the basis in `release_acceptance`.

## [2.1.0] — 2026-10-15

### Added

- `--adopt-existing` for `plan` and `sync` manages existing unmanaged profiles, such as those written by version 1, under their current names when their named session, account and role match exactly. Without it, sync proposed suffixed duplicates beside every version 1 profile. Adoption is opt-in, preserves region and output unless `--override-profile-settings` is also given, and leaves an unchanged config file byte-for-byte intact. Settings files cannot enable it.

## [2.0.1] — 2026-10-10

### Fixed

- Go installation now follows Go's version-2 module convention: `go install github.com/LanceSandino/aws-sso-profile-sync/v2@latest` selects a supported release. Pinned `@v2.0.1` installs also work.
- Installation and maintainer documentation no longer describe the public release or Homebrew formula as pending or unavailable.

### Improved

- Three clear installation methods: Homebrew, Go install, and a checksummed release archive with browser or curl download instructions.
- Compatibility tests are grouped under `tests/compatibility/`, with all original assertions preserved and both thin command entry points documented.
- Homebrew documentation links to the shared tap catalog and separates users' installation steps from formula maintenance.

The CLI commands, authentication, profile names and configuration behavior are unchanged. Go source import/install paths now include `/v2`; previously installed binaries and Homebrew users do not need to change their commands.

## [2.0.0] — 2026-10-10

### Added

- Explicit login, discover, plan, sync, list and doctor commands.
- Read-only plans with sorted before/after values and machine-readable JSON.
- Private named-session token caching, explicit refresh and device authorization.
- Optional named settings contexts for reusable SSO sessions, regions and role selections; command-line flags take precedence.
- Duplicate-profile warnings with stable identity keys, while retaining manual aliases and script-dependent names.
- Homebrew installation from a public tap and reproducible release archives, checksums, isolated installation and rollback instructions.
- Native Linux and macOS validation for Intel and ARM targets, with separate emulator tests.

### Fixed

- Valid permission-set role names containing `=` now work with command-line and settings-based role selection.
- Malformed configuration and failed writes no longer produce destructive fallbacks or false success.
- Preview commands never log in, open a browser or write token caches.
- Role and account collisions, unmanaged profile takeover and conflicting named sessions are refused.
- Missing assignments remain visible as stale profiles, including when all assignments disappear.
- Invalid tokens, canceled operations and interrupted writes return actionable failures.
- Existing profile regions and output formats are preserved, including manual edits. Changing them requires `--override-profile-settings`.

### Improved

- **Breaking:** Login is now explicit before discovery or synchronization; preview never authenticates or writes token caches.
- **Breaking:** Generated profile names include account identity to prevent collisions; existing legacy profiles stay preserved and unmanaged.

- Configuration updates preserve unrelated settings and comments, check for concurrent edits and recover known interrupted transactions.
- Authentication validates cache binding, expiry and permissions; SDK requests have bounded concurrency, retries and deadlines.
- Manual release preparation requires version-bound real AWS acceptance and owner approval, and creates a draft for review.

Real AWS IAM Identity Center and AWS CLI acceptance is tracked in the [source-bound acceptance record](.github/release-acceptance.json).

## Legacy tool — unversioned

The previously published tool discovered SSO account-role assignments and wrote
shared-config profiles using a flags-only invocation. It had no version tags or
formal semantic releases. Version 2 identifies this replacement generation; it
does not imply that a `1.0.0` release or tag previously existed.
