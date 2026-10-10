# Installation and rollback

Stable [2.0.1](https://github.com/LanceSandino/aws-sso-profile-sync/releases/tag/v2.0.1) is available through Homebrew, Go install, or a verified release archive. All four published Linux/macOS Intel/ARM archives passed native validation. Go source requires Go 1.25 or newer; validation uses Go 1.27.1. The archive installer requires Bash and Python 3. Windows is unsupported.

Published archive metadata records `NATIVE_OFFLINE_SMOKE_PASS` and real AWS acceptance `PASS`. Locally built candidates may record `NOT_RUN`; that is not a verified release. Real AWS scope is recorded in the [immutable 2.0.1 acceptance record](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json).

## Homebrew

```bash
brew install LanceSandino/tap/aws-sso-profile-sync
aws-sso-profile-sync --version
```

The public tap selects the matching macOS/Linux Intel/ARM release archive and verifies its SHA-256. Use `brew upgrade aws-sso-profile-sync` for updates or `brew uninstall aws-sso-profile-sync` to remove the executable. Homebrew installation leaves AWS configuration and tokens intact.

## Go install

Install the latest stable release with Go 1.25 or newer:

```bash
go install github.com/LanceSandino/aws-sso-profile-sync/v2@latest
"$(go env GOPATH)/bin/aws-sso-profile-sync" --version
```

If `GOBIN` is set, the executable goes there instead of `$(go env GOPATH)/bin`. Add that directory to PATH or use the full path. Pin a specific release with `go install github.com/LanceSandino/aws-sso-profile-sync/v2@v2.0.1`.

The `/v2` suffix follows [Go's major-version rules](https://go.dev/ref/mod#major-version-suffixes). The executable name stays `aws-sso-profile-sync`. Version 2.0.0 used the original suffix-free module path, which prevented ordinary tagged Go installation; 2.0.1 corrects that packaging mismatch. Use the `/v2` path for current Go installs. Existing binaries, AWS profiles and Homebrew commands are unaffected.

## Download a release archive

Download your target's archive and `SHA256SUMS` from the [2.0.1 release](https://github.com/LanceSandino/aws-sso-profile-sync/releases/tag/v2.0.1). Keep them together, verify the checksum as described below, then use the included installer with an explicit prefix.

### Download with curl

This downloads the native 2.0.1 archive, verifies its checksum before extraction, and runs the included installer. It needs Bash, Python 3, curl, tar, awk, and `shasum` (macOS) or `sha256sum` (Linux). Paste into Bash:

```bash
set -euo pipefail
case "$(uname -s)" in Darwin) platform=darwin ;; Linux) platform=linux ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) exit 1 ;; esac
version=2.0.1
archive="aws-sso-profile-sync_${version}_${platform}_${arch}.tar.gz"
release_url="https://github.com/LanceSandino/aws-sso-profile-sync/releases/download/v${version}"
download_dir=$(mktemp -d "${TMPDIR:-/tmp}/aws-sso-download.XXXXXX")
cd "$download_dir"
printf 'Downloads: %s\n' "$download_dir"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 120 --output "$archive" "$release_url/$archive"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 120 --output SHA256SUMS "$release_url/SHA256SUMS"
awk -v name="$archive" '$2 == name { print }' SHA256SUMS > SHA256SUMS.selected
test "$(wc -l < SHA256SUMS.selected)" -eq 1
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c SHA256SUMS.selected
else
  sha256sum -c SHA256SUMS.selected
fi
tar -xzf "$archive"
installer="${archive%.tar.gz}/scripts/install.sh"
/bin/bash -n "$installer"
/bin/bash "$installer" "$download_dir/$archive" --prefix "$HOME/.local"
"$HOME/.local/bin/aws-sso-profile-sync" --version
```

Add `$HOME/.local/bin` to PATH yourself if needed. The installer leaves an existing executable intact; use its explicit `--replace` option to back up and replace one. Downloads remain in the printed temporary directory; remove it after installation if you no longer need them. Nothing is piped into a shell, and the installer changes only the executable under the selected prefix.

## Build the tagged source

With Go 1.25 or newer, check out the release tag and install from that checkout:

```bash
git clone --branch v2.0.1 --depth 1 https://github.com/LanceSandino/aws-sso-profile-sync.git
cd aws-sso-profile-sync
GOBIN="$(pwd)/dist/local-bin" go install .
./dist/local-bin/aws-sso-profile-sync --version
```

If you already have the exact reviewed source checkout, start with the `GOBIN` command. It uses the root Go installation entry point and installs only that checkout's source into `dist/local-bin`.

This is an alternative to remote Go install, useful when you want to inspect the source before building.

## Build and verify release archives

All Bash scripts need syntax preflight before execution:

```bash
/bin/bash -n scripts/package.sh
/bin/bash -n scripts/install.sh
SOURCE_DATE_EPOCH=0 /bin/bash scripts/package.sh
```

The default output is `dist/2.0.1`, with native and Linux-amd64 archives plus `SHA256SUMS`. `TARGETS="darwin/amd64 linux/amd64"` and `OUTPUT_DIR=/absolute/path` override those choices. `SOURCE_DATE_EPOCH` defaults to the latest source commit timestamp; fixing it makes repeated archive timestamps reproducible. Builds use `-trimpath`, no embedded VCS metadata, and an injected version. Only the executable, README, install/manual-acceptance documents, installer, metadata LICENSE, NOTICE, third-party notices, VERSION and CHANGELOG are archived. Private specs, tokens, handoffs and test logs are excluded.

Check hashes from the archive directory:

```bash
shasum -a 256 -c SHA256SUMS
```

Linux may use `sha256sum -c SHA256SUMS`. Keep checksums with the archives. Choose the archive matching the machine; inspect `BUILD-METADATA.json` and run its executable on the target platform before claiming compatibility.

## Install into an explicit prefix

For a local isolated smoke install:

```bash
/bin/bash scripts/install.sh \
  dist/2.0.1/aws-sso-profile-sync_2.0.1_darwin_amd64.tar.gz \
  --prefix "$(pwd)/dist/test-install"
./dist/test-install/bin/aws-sso-profile-sync --version
```

Substitute `linux_amd64`, `darwin_arm64` or `linux_arm64` only when that archive was built and its target execution was verified. The installer verifies adjacent `SHA256SUMS` and matching target metadata, rejects unsafe archive entries and symlinks, and installs only the executable to `<prefix>/bin`. It does not modify PATH, shell profiles or AWS files. Running offline `doctor` during a smoke test must use an isolated HOME and config path.

An existing executable is preserved unless `--replace` is explicit. Replacement keeps a timestamped sibling backup and prints its path. Roll back by moving that specific backup over `<prefix>/bin/aws-sso-profile-sync`, after verifying the intended paths. To uninstall, remove only the installed executable; leave unrelated prefix files intact. Installation does not change configuration or tokens, so config rollback is a separate owner-managed action.

## Configuration recovery

Before any later authorized real sync, securely back up the chosen shared config and adjacent `.aws-sso-sync.json` / `.aws-sso-sync.intent` metadata as a coherent set. Preserve owner and modes. On an uncertain-write error, inspect configuration and recovery intent; do not delete ownership state or restore only one file blindly. Offline `doctor` never writes; a subsequent explicit `sync` reconciles only a recognized intent. [Manual AWS acceptance](manual-aws-acceptance.md) covers the real AWS backup/verification workflow.
