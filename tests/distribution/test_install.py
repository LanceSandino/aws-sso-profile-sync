"""Exercise the archive installer's publication race against disposable files."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / 'scripts/install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]


class InstallSafety(unittest.TestCase):
    def test_concurrent_target_requires_explicit_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'candidate.tar.gz'
            target_os = {'Darwin': 'darwin', 'Linux': 'linux'}[platform.system()]
            target_arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
            with tarfile.open(archive, 'w:gz') as tar:
                for name, data in [('candidate/BUILD-METADATA.json', json.dumps({'target': f'{target_os}/{target_arch}'}).encode()), ('candidate/aws-sso-profile-sync', b'new-candidate')]:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            (root / 'SHA256SUMS').write_text(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
            destination = root / 'install/bin/aws-sso-profile-sync'
            original_mkstemp = tempfile.mkstemp

            def concurrent_install(*args, **kwargs):
                # A different installer wins after the early target check.
                destination.write_bytes(b'other-installer-won')
                return original_mkstemp(*args, **kwargs)

            with patch.object(sys, 'argv', ['installer', str(archive), str(root / 'install'), '']), patch.object(tempfile, 'mkstemp', concurrent_install), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit, 'Existing binary preserved'):
                    exec(compile(INSTALLER, 'scripts/install.sh:python', 'exec'), {})
            self.assertEqual(destination.read_bytes(), b'other-installer-won')
            self.assertFalse(list(destination.parent.glob('*.backup-*')))
            self.assertFalse(list(destination.parent.glob('.aws-sso-install-*')))


if __name__ == '__main__':
    unittest.main()
