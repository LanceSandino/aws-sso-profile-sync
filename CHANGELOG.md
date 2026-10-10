# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes describe user-visible changes, newest first.

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
