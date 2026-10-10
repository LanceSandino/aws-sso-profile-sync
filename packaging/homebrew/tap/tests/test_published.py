"""Synthetic regressions for verifying published Homebrew release inputs."""
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
from unittest import mock
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('published', ROOT / 'scripts/published.py')
published = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(published)


class PublishedTests(unittest.TestCase):
    def archive(self, **changes):
        metadata = {'version': '2.0.0', 'target': 'darwin/amd64',
                    'execution': 'NATIVE_OFFLINE_SMOKE_PASS', 'real_aws_acceptance': 'PASS',
                    'source_date_epoch': 1}
        metadata.update(changes)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, data in {'BUILD-METADATA.json': json.dumps(metadata).encode(),
                               'aws-sso-profile-sync': b'synthetic binary',
                               'LICENSE': b'synthetic license', 'NOTICE': b'synthetic notice',
                               'THIRD_PARTY_NOTICES.md': b'synthetic dependency notice'}.items():
                info = tarfile.TarInfo(name); info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def test_stable_version_and_exact_source_required(self):
        published.validate_identity('2.0.0', 'a' * 40)
        for version in ('2.0.0-rc.1', '02.0.0', '2.0.0;echo unsafe', ''):
            with self.subTest(version=version), self.assertRaises(ValueError):
                published.validate_identity(version, 'a' * 40)
        for source in ('', 'main', 'a' * 39, 'A' * 40):
            with self.subTest(source=source), self.assertRaises(ValueError):
                published.validate_identity('2.0.0', source)

    def test_exact_four_checksums(self):
        names = published.archive_names('2.0.0')
        valid = '\n'.join('a' * 64 + '  ' + name for name in names)
        self.assertEqual(set(published.checksums(valid, names)), set(names))
        for text in (valid.split('\n', 1)[1], valid + '\n' + valid.split('\n')[0],
                     valid.replace(names[0], '../' + names[0]), valid.replace('a' * 64, 'invalid', 1)):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                published.checksums(text, names)

    def test_native_and_real_acceptance_required(self):
        actual = published.inspect_archive(self.archive(), '2.0.0', 'darwin/amd64')
        self.assertEqual(actual, hashlib.sha256(b'synthetic binary').hexdigest())
        for changes in ({'version': '1.0.0'}, {'target': 'linux/amd64'},
                        {'execution': 'NOT_RUN'}, {'real_aws_acceptance': 'PENDING'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                published.inspect_archive(self.archive(**changes), '2.0.0', 'darwin/amd64')

    def test_archive_does_not_extract_unsafe_or_duplicate_members(self):
        for name in ('../BUILD-METADATA.json', 'BUILD-METADATA.json'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                for _ in range(2):
                    member = tarfile.TarInfo(name); member.size = 2
                    archive.addfile(member, io.BytesIO(b'{}'))
            with self.subTest(name=name), self.assertRaises(ValueError):
                published.inspect_archive(stream.getvalue(), '2.0.0', 'darwin/amd64')

    def test_unexpected_symlink_member_is_rejected(self):
        stream = io.BytesIO()
        original = tarfile.open(fileobj=io.BytesIO(self.archive()), mode='r:gz')
        with original, tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for member in original.getmembers():
                archive.addfile(member, original.extractfile(member))
            member = tarfile.TarInfo('unexpected-link'); member.type = tarfile.SYMTYPE
            member.linkname = '/outside-owned-directory'
            archive.addfile(member)
        with self.assertRaises(ValueError):
            published.inspect_archive(stream.getvalue(), '2.0.0', 'darwin/amd64')

    def test_tag_commit_is_verified_not_invented_in_archive_metadata(self):
        sha = 'a' * 40
        for obj in ({'type': 'commit', 'sha': sha}, {'type': 'tag', 'sha': 'b' * 40}):
            def fetch(url):
                return {'object': obj if '/ref/' in url else {'type': 'commit', 'sha': sha}}
            self.assertEqual(published.verify_tag('2.0.0', sha, fetch), sha)
        with self.assertRaises(ValueError):
            published.verify_tag('2.0.0', sha, lambda _: {'object': {'type': 'commit', 'sha': 'c' * 40}})
        with self.assertRaises(ValueError):
            published.verify_tag('2.0.0', sha, lambda _: {'object': {'type': 'tag', 'sha': 'b' * 40}})

    def test_asset_url_boundaries(self):
        for url in ('https://github.com/valid', 'https://release-assets.githubusercontent.com/valid'):
            published.validate_url(url)
        for url in ('http://github.com/unsafe', 'https://github.com.evil.invalid/path',
                    'https://userinfo@github.com/path', 'https://amazonaws.com/path'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                published.validate_url(url)

    def test_formula_tampering_is_rejected(self):
        published.verify_formula(b'exact generated formula', b'exact generated formula')
        for changed in (b'changed archive hash', b'http://unsafe.invalid/archive', b'added ruby command'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                published.verify_formula(changed, b'exact generated formula')

    def test_corrupted_download_fails_before_generator_or_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            application = root / 'application'; application.mkdir()
            (application / 'VERSION').write_text('2.0.0')
            checksum_data = '\n'.join('a' * 64 + '  ' + name for name in published.archive_names('2.0.0')).encode()
            arguments = ['published.py', '--version', '2.0.0', '--source', 'a' * 40,
                         '--application', str(application), '--formula', str(root / 'formula.rb'),
                         '--dist', str(root / 'downloaded')]
            with mock.patch('sys.argv', arguments), mock.patch.object(published, 'verify_tag', return_value='a' * 40), \
                 mock.patch.object(published, 'download', side_effect=[checksum_data, b'corrupted archive']), \
                 mock.patch.object(published.subprocess, 'run') as generator:
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    published.main()
                generator.assert_not_called()
                self.assertFalse((root / 'downloaded' / 'receipt.json').exists())

    def test_published_workflow_is_bounded_and_preserves_public_urls(self):
        text = (ROOT / '.github/workflows/published.yml').read_text()
        self.assertIn('PUBLISHED_SOURCE_SHA', text)
        self.assertIn('timeout-minutes: 20', text)
        for runner in ('ubuntu-24.04', 'ubuntu-24.04-arm', 'macos-15-intel', 'macos-15'):
            self.assertIn(runner, text)
        self.assertNotIn('127.0.0.1', text)
        self.assertNotIn('re.sub', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('AWS_CONFIG_FILE=', text)
        self.assertLess(text.index('setup-homebrew@'), text.index('repository: LanceSandino/aws-sso-profile-sync'))


if __name__ == '__main__':
    unittest.main()
