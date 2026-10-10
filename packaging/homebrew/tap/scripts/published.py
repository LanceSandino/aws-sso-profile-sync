#!/usr/bin/env python3
"""Verify official published release inputs before native Homebrew installation."""
import argparse
import hashlib
import io
import json
import pathlib
import platform
import re
import subprocess
import tarfile
import urllib.parse
import urllib.request

PROJECT = 'LanceSandino/aws-sso-profile-sync'
TARGETS = ('darwin/amd64', 'darwin/arm64', 'linux/amd64', 'linux/arm64')
HOSTS = {'github.com', 'api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}


def validate_identity(version, source):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError('Expected canonical stable release version')
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('Expected exact published tag commit in PUBLISHED_SOURCE_SHA')


def archive_names(version):
    return ['aws-sso-profile-sync_' + version + '_' + target.replace('/', '_') + '.tar.gz'
            for target in TARGETS]


def checksums(text, names):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] not in names or match[2] in result:
            raise ValueError('Invalid, unexpected or duplicate release checksum')
        result[match[2]] = match[1]
    if set(result) != set(names):
        raise ValueError('Missing release checksum target')
    return result


def inspect_archive(data, version, target):
    root = 'aws-sso-profile-sync_' + version + '_' + target.replace('/', '_')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = {}
        for member in archive.getmembers():
            if not (member.isfile() or member.isdir()):
                raise ValueError('Release archive contains a link or special member')
            name = member.name.rstrip('/') if member.isdir() else member.name
            path = pathlib.PurePosixPath(name)
            if (not name or '\\' in name or path.is_absolute() or path.parts[0] != root
                    or any(part in ('', '.', '..') for part in name.split('/'))
                    or path.as_posix() != name or name in members):
                raise ValueError('Unsafe, unexpected-root or duplicate archive member')
            members[name] = member
        if root not in members or not members[root].isdir():
            raise ValueError('Missing expected release archive root directory')
        required = ('BUILD-METADATA.json', 'aws-sso-profile-sync', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md')
        for name in required:
            if root + '/' + name not in members or not members[root + '/' + name].isfile():
                raise ValueError('Missing regular release archive member')
        metadata_member = members[root + '/BUILD-METADATA.json']
        if metadata_member.size > 65536:
            raise ValueError('Oversized build metadata')
        metadata = json.loads(archive.extractfile(metadata_member).read())
        expected = {'version': version, 'target': target, 'execution': 'NATIVE_OFFLINE_SMOKE_PASS',
                    'real_aws_acceptance': 'PASS'}
        if not isinstance(metadata, dict) or any(metadata.get(key) != value for key, value in expected.items()):
            raise ValueError('Published archive native or real acceptance metadata differs')
        binary = members[root + '/aws-sso-profile-sync']
        if binary.size > 50 * 1024 * 1024:
            raise ValueError('Oversized release binary')
        return hashlib.sha256(archive.extractfile(binary).read()).hexdigest()


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Release download left permitted HTTPS GitHub hosts')


class GitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download(url, limit):
    validate_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), GitHubRedirects())
    request = urllib.request.Request(url, headers={'User-Agent': 'aws-sso-profile-sync-homebrew-validation'})
    with opener.open(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Release response exceeds size bound')
    return data


def fetch_json(url):
    return json.loads(download(url, 65536))


def verify_tag(version, source, fetch=fetch_json):
    validate_identity(version, source)
    url = 'https://api.github.com/repos/' + PROJECT + '/git/ref/tags/v' + version
    obj = fetch(url).get('object', {})
    for _ in range(3):
        if obj.get('type') == 'commit' and obj.get('sha') == source:
            return source
        if obj.get('type') != 'tag' or not re.fullmatch(r'[0-9a-f]{40}', obj.get('sha', '')):
            raise ValueError('Published version tag does not identify approved source')
        obj = fetch('https://api.github.com/repos/' + PROJECT + '/git/tags/' + obj['sha']).get('object', {})
    raise ValueError('Published tag resolution exceeded bound')


def verify_formula(actual, generated):
    if actual != generated:
        raise ValueError('Published formula differs from checksummed release generator output')


def native_target():
    system = platform.system().lower()
    machine = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    target = system + '/' + str(machine)
    if target not in TARGETS:
        raise ValueError('Unsupported native validation target')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('version', 'source', 'formula', 'application', 'dist'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    validate_identity(args.version, args.source)
    application = pathlib.Path(args.application).resolve()
    if (application / 'VERSION').read_text().strip() != args.version:
        raise ValueError('Trusted application generator has a different release version')
    tag_commit = verify_tag(args.version, args.source)
    dist = pathlib.Path(args.dist); dist.mkdir(parents=True, exist_ok=False)
    origin = 'https://github.com/' + PROJECT + '/releases/download/v' + args.version + '/'
    names = archive_names(args.version)
    checksum_data = download(origin + 'SHA256SUMS', 65536)
    expected = checksums(checksum_data.decode('ascii'), names)
    (dist / 'SHA256SUMS').write_bytes(checksum_data)
    binary_hashes = {}
    for target, name in zip(TARGETS, names):
        data = download(origin + name, 50 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != expected[name]:
            raise ValueError('Published archive checksum mismatch')
        binary_hashes[target] = inspect_archive(data, args.version, target)
        (dist / name).write_bytes(data)
    generated = dist / 'generated.rb'
    subprocess.run(['python3', str(application / 'scripts/homebrew.py'), '--version-file',
                    str(application / 'VERSION'), '--dist-dir', str(dist), '--output', str(generated)],
                   check=True, timeout=60)
    verify_formula(pathlib.Path(args.formula).read_bytes(), generated.read_bytes())
    target = native_target()
    receipt = {'version': args.version, 'tag_commit': tag_commit, 'archives': expected,
               'native_target': target, 'binary_sha256': binary_hashes[target]}
    (dist / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
