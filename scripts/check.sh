#!/bin/bash
# Run the non-Docker quality gates with a disposable HOME and explicit AWS paths.
set -euo pipefail
TASK_REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TASK_TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/aws-sso-check.XXXXXX")
trap 'rm -rf "$TASK_TEST_ROOT"' EXIT
for TASK_ENV_KEY in $(compgen -e); do
  case "$TASK_ENV_KEY" in AWS_*) unset "$TASK_ENV_KEY" ;; esac
done
export HOME="$TASK_TEST_ROOT" AWS_CONFIG_FILE="$TASK_TEST_ROOT/config" AWS_SHARED_CREDENTIALS_FILE="$TASK_TEST_ROOT/credentials"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true
export GOENV=off GOFLAGS= GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/aws-sso-sync-build}" GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/aws-sso-sync-mod}"
TASK_RESULTS=${CHECK_OUTPUT_DIR:-$TASK_TEST_ROOT/results}
mkdir -p "$TASK_RESULTS"
cd "$TASK_REPO_ROOT"
TASK_FORMATTED=$(gofmt -l "$TASK_REPO_ROOT/cmd" "$TASK_REPO_ROOT/internal" "$TASK_REPO_ROOT/tests" "$TASK_REPO_ROOT"/*.go)
if [ -n "$TASK_FORMATTED" ]; then printf 'Unformatted Go files:\n%s\n' "$TASK_FORMATTED" >&2; exit 1; fi
TASK_PACKAGES=$(go list -f '{{if .GoFiles}}{{.ImportPath}}{{end}}' ./... | /usr/bin/awk 'NF {if (n++) printf ","; printf "%s", $0} END {print ""}')
if [ -z "$TASK_PACKAGES" ]; then printf 'No production packages selected.\n' >&2; exit 1; fi
printf 'Production coverage scope: %s\n' "$TASK_PACKAGES"
go test -list '^Test' ./... > "$TASK_RESULTS/selected-tests.txt"
if ! /usr/bin/grep -q '^Test' "$TASK_RESULTS/selected-tests.txt"; then printf 'No unit tests selected.\n' >&2; exit 1; fi
python3 -m unittest discover -s tests/distribution -p 'test_*.py'
python3 scripts/release.py check
python3 tests/regression/test_same_name_accounts.py
go build ./...
go vet ./...
if ! go test -json -race -count=1 -timeout 3m ./... > "$TASK_RESULTS/race.jsonl"; then cat "$TASK_RESULTS/race.jsonl"; exit 1; fi
python3 - "$TASK_RESULTS/race.jsonl" <<'PY'
import json, sys
records=[json.loads(line) for line in open(sys.argv[1])]
passed=[r for r in records if r.get('Action')=='pass' and r.get('Test')]
skipped=[r for r in records if r.get('Action')=='skip' and r.get('Test')]
if not passed or skipped:
    raise SystemExit(f'Invalid test selection: {len(passed)} passes; {len(skipped)} skipped tests')
print(f'Race tests: {len(passed)} passing tests/subtests; zero skips')
PY
go test -count=1 -timeout 3m -covermode=atomic -coverpkg="$TASK_PACKAGES" -coverprofile="$TASK_RESULTS/coverage.out" ./...
go tool cover -func="$TASK_RESULTS/coverage.out" > "$TASK_RESULTS/coverage.txt"
python3 - "$TASK_RESULTS/coverage.txt" <<'PY'
import re, sys
text=open(sys.argv[1]).read()
match=re.search(r'^total:\s+\(statements\)\s+([0-9.]+)%$', text, re.M)
if not match: raise SystemExit('Missing native Go statement coverage total')
coverage=float(match.group(1))
print(f'All-production Go statement coverage: {coverage:.1f}%; branches/functions/lines: n/a as independent native dimensions')
if coverage < 85: raise SystemExit('Statement coverage is below required 85%')
PY
GOMAXPROCS=2 go test ./internal/configstore -run '^$' -fuzz '^FuzzParse$' -fuzztime 3s -parallel 2 -timeout 30s
printf 'Non-Docker gates passed. Evidence: %s\n' "$TASK_RESULTS"
