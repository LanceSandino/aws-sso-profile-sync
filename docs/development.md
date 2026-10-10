# Development and local acceptance

The module is `github.com/LanceSandino/aws-sso-profile-sync/v2`, using Go-native `cmd/` and `internal/` packages with adjacent tests. The module minimum is Go 1.25; validation currently targets Go 1.27.1. Unit tests run without Docker. Integration needs Docker and Testcontainers-Go 0.42.0.

Never develop with real AWS endpoints, actual AWS credentials, or personal AWS configuration. `scripts/check.sh` scrubs inherited `AWS_*` variables, creates a disposable HOME with explicit config/credentials paths and synthetic credentials, and uses temporary Go caches. Test-only SDK construction rejects nonloopback endpoints, inherited production credentials and paths outside the disposable root. Clients do not load default AWS configuration or IMDS.

Run from this checkout:

```bash
/bin/bash -n scripts/check.sh
GOCACHE=/private/tmp/aws-sso-sync-build \
GOMODCACHE=/private/tmp/aws-sso-sync-mod \
CHECK_OUTPUT_DIR="$(pwd)/dist/check-results" \
/bin/bash scripts/check.sh
```

On Linux, choose cache paths beneath `/tmp` instead of `/private/tmp`. The script checks formatting, enumerates every production package including both executable entry points, verifies tests were selected, builds, vets, runs race tests with zero skips, enforces total Go statement coverage at least 85%, and fuzzes the strict parser for three seconds with two workers and a 30-second hard deadline. Native Go branch coverage is n/a; separate function/line coverage dimensions are not fabricated. Omit `CHECK_OUTPUT_DIR` to keep evidence disposable.

Tests contain loopback `httptest` servers. A host sandbox denying port binds is an execution prerequisite failure, not a product failure or test pass. Run the same isolated checks with appropriate host permissions. Do not skip the boundary tests.

## Docker integration

The suite pins `floci/floci:2.2.0@sha256:e97cd0c1dc2aa14e7697fb5ef5018404c4d6345169dbd276315f0bed2c7b0520`. Testcontainers owns its disposable container. The fixture seeds synthetic Identity Store users/groups, account IDs `111111111111` and `222222222222`, read-only/power-user permission sets and direct/group assignments. It drives RegisterClient/device authorization/token creation, Portal pagination, and the compiled CLI through plan/sync/repeat/error/session/refresh scenarios.

Execute only from a clean synthetic environment. The command below creates its own HOME and strips inherited AWS variables before invoking the suite:

```bash
/bin/bash -c '
set -euo pipefail
run_root=$(mktemp -d "${TMPDIR:-/tmp}/aws-sso-integration.XXXXXX")
trap '\''rm -rf "$run_root"'\'' EXIT
for key in $(compgen -e); do case "$key" in AWS_*) unset "$key" ;; esac; done
export HOME="$run_root" AWS_CONFIG_FILE="$run_root/config" AWS_SHARED_CREDENTIALS_FILE="$run_root/credentials"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true GOENV=off GOFLAGS=
export GOCACHE="${TMPDIR:-/tmp}/aws-sso-sync-build" GOMODCACHE="${TMPDIR:-/tmp}/aws-sso-sync-mod"
go test -tags integration -list "^TestFlociCLIJourney$" ./tests/integration
go test -tags integration -v -count=1 ./tests/integration -timeout 8m
'
```

Docker absence, container startup failure, seed failure or empty test selection is FAIL/BLOCKED, never PASS. The F01–F10 subtests must execute. The local `/device` endpoint handles authorization; no real browser or AWS endpoint is used. The SDK seeder has explicit loopback endpoints and synthetic credentials for every service.

## CI and evidence

`.github/workflows/validate.yml` runs separate native Linux amd64/arm64 and macOS Intel/ARM jobs, a minimum Go 1.25 compile job, and Linux Docker integration. It uses read-only repository permissions, disables persisted checkout credentials, uses disposable paths and no AWS secrets, rejects skipped tests, and requires all F01–F10 cases. Native installation smoke runs on each target. Official actions are pinned to immutable revisions; `macos-15-intel` is listed in the [official runner image inventory](https://github.com/actions/runner-images/blob/main/README.md). The published 2.0.1 release passed all six hosted validation jobs; future changes must pass their own runs.

Real AWS acceptance for published 2.0.1 is recorded separately in the [tagged acceptance record](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json). Emulator results do not satisfy that gate. Test cache/state and raw logs do not belong in public source or release archives; see [manual acceptance](manual-aws-acceptance.md).

## Repository layout

`main.go` supports repository-path `go install`; `cmd/aws-sso-profile-sync/main.go` is the release build entry. Both are thin signal-handling wrappers around `internal/cli.Run`. Neither contains a separate implementation.

Package tests live beside `internal/` code. `tests/compatibility/` preserves the original tool's behavioral assertions and migration regressions, with test-only adapters that call the current planner, configstore and CLI. These files are compiled by `go test ./...` and are excluded from shipped executables. `tests/distribution/` verifies release, archive, installer and Homebrew tooling; `tests/integration/` owns synthetic Floci fixtures. There is no retired production implementation in the root.
