# AWS SSO Profile Sync

A Go CLI that discovers IAM Identity Center account-role assignments, previews an exact change plan, and safely manages AWS shared-config profiles. Candidate version: **0.1.0-rc.1**. Real AWS IAM Identity Center and AWS CLI acceptance remains **NOT RUN**; local emulator results do not certify production compatibility.

The tool keeps unrelated configuration and comments, refuses malformed files and ownership conflicts, and uses a locked atomic write with recovery intent. Repeating an unchanged sync preserves file bytes. Profiles missing from current assignments are reported stale and retained.

## Install

Go 1.25 or newer is required by the module; local validation/CI uses Go 1.27.1. Supported candidate targets are Linux and macOS. A cross-compiled target is not verified until executed on that platform; Windows is unsupported.

Build the reviewed candidate checkout, without accessing AWS:

```bash
GOBIN="$(pwd)/dist/local-bin" go install .
./dist/local-bin/aws-sso-profile-sync --version
```

This installs the current checkout. Remote `go install ...@latest` still resolves the published repository, which has not been updated by local candidate work. See [installation and rollback](docs/install.md) for archives, checksums, explicit prefixes and version verification.

## Commands

| Command | Behavior |
| --- | --- |
| `login` | Explicit device authorization; secure tool-owned token cache only |
| `discover` | Read-only account/role discovery with existing valid login |
| `plan` | Read-only deterministic profile changes |
| `sync` | Discovery, plan and verified transactional configuration write |
| `list` | Offline configured profiles and ownership information |
| `doctor` | Offline strict configuration diagnostics; `--probe` explicitly enables discovery |

`plan`, `discover`, `list`, offline `doctor`, and `sync --dry-run` never start login, open a browser, or write token caches. Missing or expired authentication returns `login_required`; run `login` explicitly. Re-login can recover a revoked bearer or invalid refresh grant. Malformed, insecure or mismatched cache files require inspection and correction rather than silent replacement.

For future authorized real use, follow the [owner-run manual acceptance procedure](docs/manual-aws-acceptance.md). Development and automated tests use only synthetic Floci data and disposable paths.

## Flags and migration

Use `aws-sso-profile-sync --help` for the actual defaults. Flags follow the command; repeat `--role` to select multiple roles. One available distinct role is selected with an explanation; multiple roles require an explicit choice.

| Flag | Contract |
| --- | --- |
| `--sso-start-url` | Explicit HTTPS tenant URL for network commands; never guessed |
| `--sso-session-name` | Named session; when omitted, a single matching existing session may resolve its name. An explicitly supplied `default` stays explicit |
| `--sso-region` | Identity Center region, default `us-east-1` |
| `--region` | Profile region: flag → `AWS_REGION` → `AWS_DEFAULT_REGION` → existing `[default]` → `us-east-2` |
| `--role` | Exact assigned role, repeatable |
| `--prefix`, `--auto-prefix` | Naming prefix; account ID and stable identity suffix prevent role/account collisions |
| `--output` | AWS profile output setting, default `json`; separate from CLI formatting |
| `--format` | CLI `table` or versioned `json`, default `table` |
| `--config-file` | Target shared config; `AWS_CONFIG_FILE` or `~/.aws/config` by default |
| `--state-dir` | Private token state root, default `~/.aws-sso-profile-sync` |
| `--dry-run` | Maps `sync` to strictly read-only `plan` |
| `--open=false` | Present the explicit login verification URL without opening a browser |
| `--timeout` | Invocation deadline, default `2m`, maximum `10m` |
| `--probe` | Explicit network discovery for `doctor` |
| `--test-root`, `--test-endpoint` | Isolated loopback emulator mode for development |

Flags-only legacy invocation maps to `sync`; it now requires a separately completed explicit login. Existing single-dash flag spellings also work. Names use sanitized labels, account ID and identity suffix; old manually configured profiles remain unmanaged and are preserved. There is no automatic adoption or deletion operation.

## JSON and failures

`--format json` emits a schema-version-1 envelope on stdout with `command`, `status`, `results`, `assignments`, `counts`, and an optional nonsecret `error`. Plans include proposed section changes, a structured `diff` of before/after values, and before/after configuration hashes. Progress and errors go to stderr; JSON has no ANSI escapes or tokens. Table output uses no color, so `NO_COLOR` is respected.

Profile results include `created`, `updated`, `unchanged`, `conflict`, and informational `stale`. Invalid configuration, role selection, login, discovery, conflicts, canceled/deadline operations, and uncertain writes return a nonzero exit. An interrupted write may have committed configuration while retaining recovery intent: inspect the files and rerun offline `doctor`; do not assume every error means the original file remains unchanged.

## State and safety

Tokens live under `<state-dir>/auth`, scoped to named session, start URL, SSO region and endpoint. Cache directories/files use owner-only permissions. The tool does not import timestamp-selected AWS CLI token caches. AWS CLI token interoperability and real refresh remain pending manual acceptance.

For a config at `CONFIG`, tool metadata is adjacent: `CONFIG.aws-sso-sync.json`, `CONFIG.aws-sso-sync.intent`, and `CONFIG.aws-sso-sync.lock`. Keep these with backups. Ownership metadata authorizes updates only to matching managed identities; changing a profile externally may produce a conflict. Symlinks are refused except standard macOS system path aliases. Read-only commands do not create or reconcile files; the next explicit sync handles a proven recoverable intent.

## Development

[Development and local acceptance](docs/development.md) describes isolated unit/race/coverage/fuzz checks and pinned Floci/Testcontainers integration. The CLI has no GUI, daemon, AWS CLI dependency, or automatic cloud provisioning.

Licensed under [Apache-2.0](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).

Versioning, owner approval, release tags and Homebrew updates are described in [release instructions](docs/releasing.md). Homebrew installation will be available after the owner publishes a release and the prepared tap; no release is published by this candidate branch.
