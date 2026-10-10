"""Exercise the public v2 Go installation entry points in an isolated HOME."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = 'github.com/LanceSandino/aws-sso-profile-sync/v2'


class GoInstallTests(unittest.TestCase):
    def test_public_module_entry_points_install_and_report_correct_version(self):
        with tempfile.TemporaryDirectory(prefix='aws-sso-go-install-') as directory:
            root = pathlib.Path(directory)
            home = root / 'home'; home.mkdir(mode=0o700)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith('AWS_')}
            environment.update(HOME=str(home), GOBIN=str(root / 'bin'),
                               GOPATH=str(root / 'go'), GOENV='off', GOWORK='off',
                               GOFLAGS='-mod=readonly -p=2', GOMAXPROCS='2',
                               AWS_CONFIG_FILE=str(home / 'config'),
                               AWS_SHARED_CREDENTIALS_FILE=str(home / 'credentials'),
                               AWS_EC2_METADATA_DISABLED='true')
            environment.setdefault('GOCACHE', str(root / 'build-cache'))
            environment.setdefault('GOMODCACHE', str(root / 'module-cache'))

            def run(arguments):
                result = subprocess.run(arguments, cwd=ROOT, env=environment,
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout + result.stderr

            binary = str(root / 'bin/aws-sso-profile-sync')
            # The ordinary repository-path install must resolve to this module.
            run(['go', 'install', MODULE])
            self.assertEqual(run([binary, '--version']).strip(),
                             (ROOT / 'VERSION').read_text().strip())
            self.assertIn('sync', run([binary, '--help']))
            # Release packaging uses cmd/ and injects this exact linker symbol.
            injected = '0.0.0+install.smoke'
            run(['go', 'install', '-ldflags=-X '+MODULE+'/internal/cli.Version='+injected,
                 MODULE+'/cmd/aws-sso-profile-sync'])
            self.assertEqual(run([binary, '--version']).strip(), injected)
            self.assertIn('doctor', run([binary, '--help']))
            self.assertFalse((home / 'config').exists())
            self.assertFalse((home / 'credentials').exists())


if __name__ == '__main__':
    unittest.main()
