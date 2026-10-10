# Installation and rollback

Version `2.0.0` is the first semantic release of this rewrite. Go source requires Go 1.25 or newer; the checked validation toolchain is Go 1.27.1. Supported targets are Linux/macOS. Read each archive's `BUILD-METADATA.json`: `NOT_RUN` means cross-compilation only, while `NATIVE_OFFLINE_SMOKE_PASS` records native version/help/offline-doctor execution. Full local acceptance is recorded separately in repository evidence. Windows is unsupported.

## Homebrew

```bash
brew install LanceSandino/tap/aws-sso-profile-sync
aws-sso-profile-sync --version
```

The public tap selects the matching macOS/Linux Intel/ARM release archive and verifies its SHA-256. Use `brew upgrade aws-sso-profile-sync` for updates or `brew uninstall aws-sso-profile-sync` to remove the executable. Homebrew installation leaves AWS configuration and tokens intact.

## Download a release archive

Download your target's archive and `SHA256SUMS` from the [2.0.0 release](https://github.com/LanceSandino/aws-sso-profile-sync/releases/tag/v2.0.0). Keep them together, verify the checksum as described below, then use the included installer with an explicit prefix.

## Build the reviewed source

At the exact reviewed source checkout:

```bash
GOBIN="$(pwd)/dist/local-bin" go install .
./dist/local-bin/aws-sso-profile-sync --version
```

This uses the root canonical Go installation entry point. `go install github.com/LanceSandino/aws-sso-profile-sync@latest` resolves remote source and will not install unpublished local changes.

## Build and verify release archives

All Bash scripts need syntax preflight before execution:

```bash
/bin/bash -n scripts/package.sh
/bin/bash -n scripts/install.sh
SOURCE_DATE_EPOCH=0 /bin/bash scripts/package.sh
```

The default output is `dist/2.0.0`, with native and Linux-amd64 archives plus `SHA256SUMS`. `TARGETS="darwin/amd64 linux/amd64"` and `OUTPUT_DIR=/absolute/path` override those choices. `SOURCE_DATE_EPOCH` defaults to the latest source commit timestamp; fixing it makes repeated archive timestamps reproducible. Builds use `-trimpath`, no embedded VCS metadata, and an injected version. Only the executable, README, install/manual-acceptance documents, installer, metadata LICENSE, NOTICE, third-party notices, VERSION and CHANGELOG are archived. Private specs, tokens, handoffs and test logs are excluded.

Check hashes from the archive directory:

```bash
shasum -a 256 -c SHA256SUMS
```

Linux may use `sha256sum -c SHA256SUMS`. Keep checksums with the archives. Choose the archive matching the machine; inspect `BUILD-METADATA.json` and run its executable on the target platform before claiming compatibility.

## Install into an explicit prefix

For a local isolated smoke install:

```bash
/bin/bash scripts/install.sh \
  dist/2.0.0/aws-sso-profile-sync_2.0.0_darwin_amd64.tar.gz \
  --prefix "$(pwd)/dist/test-install"
./dist/test-install/bin/aws-sso-profile-sync --version
```

Substitute `linux_amd64`, `darwin_arm64` or `linux_arm64` only when that archive was built and its target execution was verified. The installer verifies adjacent `SHA256SUMS` and matching target metadata, rejects unsafe archive entries and symlinks, and installs only the executable to `<prefix>/bin`. It does not modify PATH, shell profiles or AWS files. Running offline `doctor` during a smoke test must use an isolated HOME and config path.

An existing executable is preserved unless `--replace` is explicit. Replacement keeps a timestamped sibling backup and prints its path. Roll back by moving that specific backup over `<prefix>/bin/aws-sso-profile-sync`, after verifying the intended paths. To uninstall, remove only the installed executable; leave unrelated prefix files intact. Installation does not change configuration or tokens, so config rollback is a separate owner-managed action.

## Configuration recovery

Before any later authorized real sync, securely back up the chosen shared config and adjacent `.aws-sso-sync.json` / `.aws-sso-sync.intent` metadata as a coherent set. Preserve owner and modes. On an uncertain-write error, inspect configuration and recovery intent; do not delete ownership state or restore only one file blindly. Offline `doctor` never writes; a subsequent explicit `sync` reconciles only a recognized intent. [Manual AWS acceptance](manual-aws-acceptance.md) covers the real AWS backup/verification workflow.
