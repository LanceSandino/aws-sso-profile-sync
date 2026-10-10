# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes describe user-visible changes, newest first.

## [2.0.0-rc.1] — Unreleased

### Added

- Explicit login, discover, plan, sync, list and doctor commands.
- Read-only plans with sorted before/after values and machine-readable JSON.
- Private named-session token caching, explicit refresh and device authorization.
- Reproducible candidate archives, checksums, isolated installation and rollback instructions.
- Native Linux and macOS validation for Intel and ARM targets, with separate emulator tests.

### Fixed

- Malformed configuration and failed writes no longer produce destructive fallbacks or false success.
- Preview commands never log in, open a browser or write token caches.
- Role and account collisions, unmanaged profile takeover and conflicting named sessions are refused.
- Missing assignments remain visible as stale profiles, including when all assignments disappear.
- Invalid tokens, canceled operations and interrupted writes return actionable failures.

### Improved

- **Breaking:** Login is now explicit before discovery or synchronization; preview never authenticates or writes token caches.
- **Breaking:** Generated profile names include account identity to prevent collisions; existing legacy profiles stay preserved and unmanaged.

- Configuration updates preserve unrelated settings and comments, check for concurrent edits and recover known interrupted transactions.
- Authentication validates cache binding, expiry and permissions; SDK requests have bounded concurrency, retries and deadlines.
- Manual release preparation requires version-bound real AWS acceptance and owner approval, and creates a draft for review.

Real AWS IAM Identity Center and AWS CLI acceptance remains pending. No release has been published.

## Legacy tool — unversioned

The previously published tool discovered SSO account-role assignments and wrote
shared-config profiles using a flags-only invocation. It had no version tags or
formal semantic releases. Version 2 identifies this replacement generation; it
does not imply that a `1.0.0` release or tag previously existed.
