#!/bin/bash
# Build deterministic local candidate archives; no publication or real AWS operations.
set -euo pipefail
TASK_REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -n "${VERSION:-}" ]; then
  TASK_VERSION=$(python3 "$TASK_REPO_ROOT/scripts/release.py" version --expect "$VERSION")
else
  TASK_VERSION=$(python3 "$TASK_REPO_ROOT/scripts/release.py" version)
fi
python3 "$TASK_REPO_ROOT/scripts/release.py" check
TASK_BUILD_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/aws-sso-package.XXXXXX")
trap 'rm -rf "$TASK_BUILD_ROOT"' EXIT
for TASK_ENV_KEY in $(compgen -e); do case "$TASK_ENV_KEY" in AWS_*) unset "$TASK_ENV_KEY" ;; esac; done
export HOME="$TASK_BUILD_ROOT/home" AWS_CONFIG_FILE="$TASK_BUILD_ROOT/home/config" AWS_SHARED_CREDENTIALS_FILE="$TASK_BUILD_ROOT/home/credentials"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true
export GOENV=off GOFLAGS= GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/aws-sso-sync-build}" GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/aws-sso-sync-mod}"
mkdir -p "$HOME"
cd "$TASK_REPO_ROOT"
TASK_ACCEPTANCE=NOT_RUN
if python3 scripts/release.py gate > "$TASK_BUILD_ROOT/acceptance.txt" 2>&1; then TASK_ACCEPTANCE=PASS; fi
TASK_NATIVE_OS=$(go env GOHOSTOS)
TASK_NATIVE_ARCH=$(go env GOHOSTARCH)
case "$TASK_NATIVE_OS" in darwin|linux) ;; *) printf 'Candidate packaging supports Linux/macOS only.\n' >&2; exit 1 ;; esac
TASK_OUT=${OUTPUT_DIR:-$TASK_REPO_ROOT/dist/$TASK_VERSION}
mkdir -p "$TASK_OUT"
TASK_OUT=$(cd "$TASK_OUT" && pwd)
TASK_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
case "$TASK_EPOCH" in *[!0-9]*|'') printf 'Invalid SOURCE_DATE_EPOCH.\n' >&2; exit 1 ;; esac
TASK_TARGETS=${TARGETS:-$TASK_NATIVE_OS/$TASK_NATIVE_ARCH linux/amd64}
TASK_SEEN=' '
for TASK_TARGET in $TASK_TARGETS; do
  case "$TASK_SEEN" in *" $TASK_TARGET "*) continue ;; esac
  TASK_SEEN="$TASK_SEEN$TASK_TARGET "
  TASK_OS=${TASK_TARGET%/*}; TASK_ARCH=${TASK_TARGET#*/}
  case "$TASK_TARGET" in darwin/amd64|darwin/arm64|linux/amd64|linux/arm64) ;; *) printf 'Unsupported target %s\n' "$TASK_TARGET" >&2; exit 1 ;; esac
  TASK_NAME="aws-sso-profile-sync_${TASK_VERSION}_${TASK_OS}_${TASK_ARCH}"
  TASK_STAGE="$TASK_BUILD_ROOT/$TASK_NAME"
  mkdir -p "$TASK_STAGE/docs" "$TASK_STAGE/scripts"
  CGO_ENABLED=0 GOOS="$TASK_OS" GOARCH="$TASK_ARCH" go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X github.com/LanceSandino/aws-sso-profile-sync/v2/internal/cli.Version=$TASK_VERSION" -o "$TASK_STAGE/aws-sso-profile-sync" ./cmd/aws-sso-profile-sync
  cp README.md "$TASK_STAGE/README.md"
  cp docs/install.md docs/manual-aws-acceptance.md docs/usage.md docs/architecture.md docs/development.md docs/releasing.md "$TASK_STAGE/docs/"
  cp scripts/install.sh "$TASK_STAGE/scripts/"
  cp LICENSE NOTICE THIRD_PARTY_NOTICES.md VERSION CHANGELOG.md "$TASK_STAGE/"
  TASK_EXECUTION=NOT_RUN
  if [ "$TASK_TARGET" = "$TASK_NATIVE_OS/$TASK_NATIVE_ARCH" ]; then
    TASK_ACTUAL=$("$TASK_STAGE/aws-sso-profile-sync" --version)
    if [ "$TASK_ACTUAL" != "$TASK_VERSION" ]; then printf 'Candidate version mismatch.\n' >&2; exit 1; fi
    "$TASK_STAGE/aws-sso-profile-sync" --help > "$TASK_BUILD_ROOT/help.txt" 2>&1
    "$TASK_STAGE/aws-sso-profile-sync" doctor --format json > "$TASK_BUILD_ROOT/doctor.json"
    python3 - "$TASK_BUILD_ROOT/doctor.json" <<'PY'
import json, sys
value=json.load(open(sys.argv[1]))
assert value['schema_version']==1 and value['command']=='doctor' and value['status']=='ok'
PY
    TASK_EXECUTION=NATIVE_OFFLINE_SMOKE_PASS
  fi
  python3 - "$TASK_STAGE" "$TASK_OUT/$TASK_NAME.tar.gz" "$TASK_EPOCH" "$TASK_VERSION" "$TASK_TARGET" "$TASK_EXECUTION" "$TASK_ACCEPTANCE" <<'PY'
import gzip, json, pathlib, tarfile, sys
stage, archive, epoch, version, target, execution, acceptance=sys.argv[1:]
root=pathlib.Path(stage); epoch=int(epoch)
(root/'BUILD-METADATA.json').write_text(json.dumps({'version':version,'target':target,'source_date_epoch':epoch,'execution':execution,'real_aws_acceptance':acceptance},sort_keys=True)+'\n')
with open(archive,'wb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as tar:
    for path in [root]+sorted(root.rglob('*')):
        info=tar.gettarinfo(str(path),arcname=str(path.relative_to(root.parent)))
        info.uid=info.gid=0; info.uname=info.gname='';info.mtime=epoch
        info.mode=0o755 if info.isdir() or path.name in ('aws-sso-profile-sync','install.sh') else 0o644
        info.pax_headers={}
        if info.isfile():
            with path.open('rb') as source: tar.addfile(info,source)
        else: tar.addfile(info)
print(f'Candidate: {archive}; {execution}')
PY
done
python3 - "$TASK_OUT" <<'PY'
import hashlib, pathlib, sys
root=pathlib.Path(sys.argv[1]);archives=sorted(root.glob('aws-sso-profile-sync_*.tar.gz'))
if not archives: raise SystemExit('No archives produced')
(root/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in archives))
PY
printf 'Local candidate archives and SHA256SUMS: %s\n' "$TASK_OUT"
