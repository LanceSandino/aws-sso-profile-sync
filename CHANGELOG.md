# Changelog

## 0.1.0-rc.1 (unreleased)

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

- Configuration updates preserve unrelated settings and comments, check for concurrent edits and recover known interrupted transactions.
- Authentication validates cache binding, expiry and permissions; SDK requests have bounded concurrency, retries and deadlines.
- Manual release preparation requires version-bound real AWS acceptance and owner approval, and creates a draft for review.

Real AWS IAM Identity Center and AWS CLI acceptance remains pending. No release has been published.
