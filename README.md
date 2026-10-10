# AWS SSO Profile Sync

AWS SSO Profile Sync is a Go CLI that turns your AWS IAM Identity Center account and role assignments into named AWS shared-config profiles. It helps keep profiles current as access changes, with a reviewable plan before writing configuration.

## Why I built it

Managing SSO profiles across many AWS accounts meant repetitive configuration work and profiles that drifted as access changed. I couldn't find a tool that fit my workflow, so I built the original flags-only version. I used it daily across more than 50 AWS accounts at multiple companies.

Version **2.0.0** replaced that original implementation with explicit authentication, deterministic planning and guarded configuration updates. **2.0.1** fixes Go module installation and clarifies installation and maintenance documentation. The original tool's field use is separate from this rewrite's validation. Releases have native validation on all four supported targets, synthetic Floci integration, and [source-bound real IAM Identity Center and AWS CLI acceptance](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json). Real acceptance covers two named sessions and two profile regions at one Identity Center region; it does not certify every AWS environment.

## What it does

- Discovers the AWS accounts and roles assigned to your signed-in user, including paginated results.
- Saves repeated nonsecret options in an optional settings file, with named contexts for different SSO sessions.
- Selects one or several roles and creates distinct profile names from the account label, account ID and a stable identity suffix.
- Shows proposed changes and before/after values in a table or versioned JSON; JSON also includes configuration hashes.
- Preserves unrelated profiles, settings and comments. Existing unmanaged profiles are never silently adopted.
- Reports removed assignments as stale and retains their profiles for review.
- Preserves existing profile regions and output settings by default, with warnings when requested defaults differ. Explicit `--override-profile-settings` authorizes changing those settings on managed profiles.
- Reports duplicate identity aliases without deleting, merging or adopting them.
- Refuses malformed configuration, conflicting session bindings, externally edited managed identities and concurrent changes.
- Uses bounded requests, advisory locking, atomic file replacement and recoverable ownership metadata; unchanged syncs preserve file bytes.

It is a CLI, with no GUI, daemon, cloud provisioning or AWS CLI installation dependency. AWS CLI interoperability is verified separately through real acceptance testing.

## Installation

### Homebrew (macOS and Linux)

```bash
brew install LanceSandino/tap/aws-sso-profile-sync
aws-sso-profile-sync --version
```

The public [Homebrew tap](https://github.com/LanceSandino/homebrew-tap) installs the matching release archive and verifies its checksum. Upgrade with `brew upgrade aws-sso-profile-sync`.

### Go install

With Go 1.25 or newer:

```bash
go install github.com/LanceSandino/aws-sso-profile-sync/v2@latest
"$(go env GOPATH)/bin/aws-sso-profile-sync" --version
```

If you set `GOBIN`, use that directory instead. Add the install directory to PATH or use the executable's full path. To pin this release, replace `@latest` with `@v2.0.1`. The `/v2` suffix is Go's standard module path for major version 2; the binary is still named `aws-sso-profile-sync`. [Tagged-checkout installation](docs/install.md#build-the-tagged-source) also supports `go install .`.

### Release archive (browser or curl)

Download your platform's archive and `SHA256SUMS` from the [2.0.1 release](https://github.com/LanceSandino/aws-sso-profile-sync/releases/tag/v2.0.1). Verify its checksum, then use the included installer with an explicit prefix. The [curl walkthrough](docs/install.md#download-with-curl) selects the native target, downloads and verifies the archive, and installs it without Go or Homebrew. It requires Bash, Python 3, curl, tar and a SHA-256 checker.

Supported targets are **Linux amd64/arm64 and macOS amd64/arm64**. Windows is unsupported. Each target has native build, test, archive installation and offline diagnostic validation.

## Walkthrough

Start with the [complete usage guide](docs/usage.md), which covers setup, authentication, discovery, role selection, profile naming, previews, synchronization and recovery. Back up your chosen config and adjacent ownership metadata before the first sync. The [manual acceptance procedure](docs/manual-aws-acceptance.md) is for maintainers validating a new release or operators checking another environment.

The typical sequence is **login → discover → plan → review → sync**. This Bash example uses a placeholder tenant URL; replace it only for an authorized session. Choose the assigned role reported by discovery rather than assuming `ReadOnly` exists:

```bash
session_flags=(
  --sso-start-url https://example.invalid/start
  --sso-session-name work
  --sso-region us-east-1
  --config-file "$HOME/.aws/config"
  --state-dir "$HOME/.aws-sso-profile-sync"
)

aws-sso-profile-sync login "${session_flags[@]}" --open=false
aws-sso-profile-sync discover "${session_flags[@]}"
aws-sso-profile-sync plan "${session_flags[@]}" --role ReadOnly --region us-east-2

# After reviewing the plan, explicitly apply it:
aws-sso-profile-sync sync "${session_flags[@]}" --role ReadOnly --region us-east-2
aws-sso-profile-sync list --config-file "$HOME/.aws/config"
aws-sso-profile-sync doctor --config-file "$HOME/.aws/config"
```

`login` performs device authorization. `--open=false` prints the verification URL without opening a browser. One available distinct role is selected with an explanation; multiple available roles require an explicit choice. Repeat `--role` to select more than one.

| Command | Purpose |
| --- | --- |
| `login` | Explicit device authorization and private tool-owned token caching |
| `discover` | Read-only account and role discovery using an existing valid login |
| `plan` | Read-only deterministic configuration plan |
| `sync` | Discovery, planning and a verified configuration transaction |
| `list` | Offline profile and ownership information |
| `doctor` | Offline configuration diagnostics; `--probe` explicitly adds network discovery |

`plan`, `discover`, `list`, offline `doctor` and `sync --dry-run` never start login, open a browser or write token caches. Missing or expired authentication returns `login_required`; run `login` explicitly. Re-login can recover a revoked token or invalid refresh grant. Malformed, insecure or mismatched caches require inspection instead of silent replacement.

Use `--format json` for CLI output; `--output` controls the AWS profile's output setting. `--prefix` and `--auto-prefix` control the readable portion of profile names. Flags follow the command. Run `aws-sso-profile-sync --help` for all flags and defaults, and see the [usage guide](docs/usage.md) for region precedence and detailed examples.

The original flags-only invocation still maps to `sync`, and single-dash flag spellings work. It now requires a separately completed login. Profile names have changed; old manually configured profiles stay unmanaged and preserved. There is no automatic adoption or deletion operation.

## Optional settings and contexts

For repeated use, put the tenant, named session, regions, roles and file paths in an optional JSON settings file. Named contexts let you switch between SSO sessions without repeating the same flags:

```bash
aws-sso-profile-sync login --context work --open=false
aws-sso-profile-sync plan --context work
aws-sso-profile-sync sync --context work
```

`--context` reads `~/.aws-sso-profile-sync/settings.json`; `--settings-file FILE` selects another file. Nothing is loaded unless one of those flags is supplied, and the tool never creates or updates settings. Explicit flags override context defaults, including replacing configured roles. Multiple contexts require a selected context or a declared default. Settings contain no tokens or credentials, and selecting a context does not log in.

See [settings format and examples](docs/usage.md#optional-settings-and-contexts) for the schema, path rules and a complete example.

## Configuration and recovery

Tokens are stored under `<state-dir>/auth`, bound to the named session, start URL, SSO region and endpoint, with owner-only permissions. The tool does not select or import AWS CLI token caches by timestamp.

For a config at `CONFIG`, ownership and recovery files are adjacent: `CONFIG.aws-sso-sync.json`, `CONFIG.aws-sso-sync.intent` and `CONFIG.aws-sso-sync.lock`. Keep these with configuration backups. Read-only commands do not create or reconcile them; a later explicit sync reconciles a recognized interrupted transaction. Arbitrary symlink paths are refused, with standard macOS system aliases allowed.

Failures return a nonzero exit code. A write error can mean that configuration was committed while recovery intent remains. Inspect the files and run offline `doctor` before retrying; do not assume every error means the original file is unchanged. The [usage guide](docs/usage.md) and [recovery instructions](docs/install.md#configuration-recovery) explain the next steps.

## Architecture and design decisions

The code uses Go-native packages with explicit boundaries:

| Package | Responsibility |
| --- | --- |
| `internal/cli` | Commands, flags, output and coordination |
| `internal/domain` | Shared session, assignment, profile and error contracts |
| `internal/settings` | Read-only nonsecret context defaults and strict file validation |
| `internal/auth` | Explicit login, token validation, refresh and private caching |
| `internal/awsclient` | SDK construction and isolated emulator endpoint policy |
| `internal/discovery` | Account and role enumeration with bounded concurrency |
| `internal/planner` | Pure naming, role selection, ownership checks and change planning |
| `internal/configstore` | Strict parsing, exact previews and guarded transactions |

Authentication is explicit so a preview cannot unexpectedly sign in or change a cache. Managed profiles have stable identities so label changes do not create replacement profiles. Ownership checks protect existing configuration, existing region/output settings stay intact unless explicitly overridden, and stale profiles are retained so lost access does not trigger deletion. Durable recovery intent connects configuration writes with ownership metadata across interruptions.

Read [architecture and public design decisions](docs/architecture.md) for the data flow, storage model and tradeoffs.

## Testing and contributing

[Development instructions](docs/development.md) describe isolated build, vet, race, coverage and fuzz checks, plus real Floci/Testcontainers integration with synthetic accounts, roles, permission sets and device authorization. Development tests use disposable HOME/config/state paths and never access real AWS endpoints, actual credentials or personal AWS configuration. Go statement coverage is enforced at **85% or higher**.

Native CI targets all four supported platforms and runs a separate Floci integration job. See the [release acceptance record](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json) for source-bound real AWS results and the observed scope. Development and CI use synthetic data only.

See the [changelog](CHANGELOG.md) for user-visible changes and [release instructions](docs/releasing.md) for versioning, acceptance and owner-controlled publication.

Licensed under [Apache-2.0](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
