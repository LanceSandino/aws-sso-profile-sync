#!/bin/bash
# Verify an archive and install only its executable into an explicitly chosen prefix.
set -euo pipefail
if [ "$#" -lt 3 ] || [ "$2" != --prefix ]; then printf 'Usage: /bin/bash scripts/install.sh ARCHIVE --prefix ABSOLUTE_PREFIX [--replace]\n' >&2; exit 2; fi
TASK_ARCHIVE=$1; TASK_PREFIX=$3; TASK_REPLACE=${4:-}
if [ "$#" -gt 4 ] || { [ -n "$TASK_REPLACE" ] && [ "$TASK_REPLACE" != --replace ]; }; then printf 'Unexpected install arguments.\n' >&2; exit 2; fi
case "$TASK_PREFIX" in /*) ;; *) printf 'Prefix must be an explicit absolute path.\n' >&2; exit 2 ;; esac
python3 - "$TASK_ARCHIVE" "$TASK_PREFIX" "$TASK_REPLACE" <<'PY'
import hashlib, json, os, pathlib, platform, shutil, sys, tarfile, tempfile, time
archive=pathlib.Path(sys.argv[1]).resolve();prefix=pathlib.Path(sys.argv[2]);replace=sys.argv[3]=='--replace'
if not archive.is_file(): raise SystemExit('Candidate archive does not exist')
checksums=archive.parent/'SHA256SUMS'
if not checksums.is_file(): raise SystemExit('Adjacent SHA256SUMS is required')
expected={name:digest for digest,name in (line.split(maxsplit=1) for line in checksums.read_text().splitlines())}
if expected.get(archive.name)!=hashlib.sha256(archive.read_bytes()).hexdigest(): raise SystemExit('Candidate checksum mismatch')
for parent in [prefix,*prefix.parents]:
    if parent.is_symlink() and str(parent) not in ('/var','/tmp'): raise SystemExit('Install prefix contains a symlink')
bindir=prefix/'bin'
if bindir.is_symlink(): raise SystemExit('Install bin directory is a symlink')
bindir.mkdir(parents=True,exist_ok=True)
destination=bindir/'aws-sso-profile-sync'
if destination.is_symlink() or (destination.exists() and not destination.is_file()): raise SystemExit('Unsafe existing install target')
if destination.exists() and not replace: raise SystemExit('Existing binary preserved; use --replace to keep a backup and replace it')
with tarfile.open(archive,'r:gz') as tar:
    entries=tar.getmembers()
    for member in entries:
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()): raise SystemExit('Unsafe candidate archive entry')
    metadata=[m for m in entries if m.isfile() and pathlib.PurePosixPath(m.name).name=='BUILD-METADATA.json']
    if len(metadata)!=1 or metadata[0].size>65536: raise SystemExit('Candidate build metadata is missing or invalid')
    info=json.load(tar.extractfile(metadata[0]))
    native_os={'Darwin':'darwin','Linux':'linux'}.get(platform.system())
    native_arch={'x86_64':'amd64','AMD64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine())
    if not native_os or not native_arch or info.get('target')!=f'{native_os}/{native_arch}': raise SystemExit('Candidate target does not match this machine')
    binaries=[m for m in entries if m.isfile() and pathlib.PurePosixPath(m.name).name=='aws-sso-profile-sync']
    if len(binaries)!=1: raise SystemExit('Archive must contain exactly one executable')
    member=binaries[0]
    if member.size>100*1024*1024: raise SystemExit('Candidate executable exceeds size limit')
    source=tar.extractfile(member)
    fd,temporary=tempfile.mkstemp(prefix='.aws-sso-install-',dir=bindir)
    try:
        with os.fdopen(fd,'wb') as output: shutil.copyfileobj(source,output);output.flush();os.fsync(output.fileno())
        os.chmod(temporary,0o755)
        if replace:
            if destination.exists():
                backup=bindir/f'aws-sso-profile-sync.backup-{time.time_ns()}'
                shutil.copy2(destination,backup)
                print(f'Rollback backup: {backup}')
            os.replace(temporary,destination)
        else:
            # Atomic no-replace publication also protects a target created
            # after the initial check by another concurrent installer.
            try: os.link(temporary,destination)
            except FileExistsError: raise SystemExit('Existing binary preserved; use --replace to keep a backup and replace it')
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
print(f'Installed: {destination}')
PY
