"""Verify deterministic Homebrew output from isolated synthetic release archives."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/homebrew.py"
TARGETS = (("darwin", "amd64"), ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"))


class HomebrewFormula(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.version = self.root / "VERSION"
        self.version.write_text("1.2.3-rc.1\n")
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.output = self.root / "aws-sso-profile-sync.rb"

        self.archives("1.2.3-rc.1")

    def archives(self, version):
        self.version.write_text(version + "\n")
        for path in self.dist.glob("*.tar.gz"):
            path.unlink()
        for os_name, arch in TARGETS:
            name = f"aws-sso-profile-sync_{version}_{os_name}_{arch}"
            with tarfile.open(self.dist / f"{name}.tar.gz", "w:gz") as archive:
                for filename, data in {
                    "BUILD-METADATA.json": json.dumps({"version": version, "target": f"{os_name}/{arch}"}).encode(),
                    "aws-sso-profile-sync": b"synthetic binary",
                    "LICENSE": b"synthetic license",
                    "NOTICE": b"synthetic notice",
                    "THIRD_PARTY_NOTICES.md": b"synthetic dependency notices",
                }.items():
                    info = tarfile.TarInfo(f"{name}/{filename}")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        self.checksums()

    def checksums(self):
        (self.dist / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(self.dist.glob("*.tar.gz"))))

    def run_generator(self):
        return subprocess.run([sys.executable, str(GENERATOR), "--version-file", str(self.version),
                               "--dist-dir", str(self.dist), "--output", str(self.output)],
                              capture_output=True, text=True, timeout=10)

    def failure(self, expected):
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stderr)
        self.assertFalse(self.output.exists(), "failed validation wrote a formula")

    def test_exact_urls_hashes_and_offline_formula_smoke(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.output.read_bytes()
        formula = before.decode()
        for path in self.dist.glob("*.tar.gz"):
            self.assertIn(f"https://github.com/LanceSandino/aws-sso-profile-sync/releases/download/v1.2.3-rc.1/{path.name}", formula)
            self.assertIn(hashlib.sha256(path.read_bytes()).hexdigest(), formula)
        for token in ('license "Apache-2.0"', 'on_macos do', 'on_linux do', 'on_arm do', 'on_intel do',
                      'bin.install "aws-sso-profile-sync"', 'THIRD_PARTY_NOTICES.md',
                      '--version', '"doctor"', '--config-file', 'ENV["HOME"]',
                      'AWS_SHARED_CREDENTIALS_FILE', 'AWS_EC2_METADATA_DISABLED'):
            self.assertIn(token, formula)
        self.assertNotIn('"login"', formula)
        self.assertNotIn('"discover"', formula)
        self.assertEqual(self.run_generator().returncode, 0)
        self.assertEqual(self.output.read_bytes(), before)

    def test_missing_target_is_rejected(self):
        next(self.dist.glob("*linux_arm64.tar.gz")).unlink()
        self.checksums()
        self.failure("four target archives")

    def test_formula_stays_within_homebrew_line_length(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        for number, line in enumerate(self.output.read_text().splitlines(), 1):
            # URL lines are explicitly exempt in Homebrew's formula style.
            if 'url "https://' not in line:
                self.assertLessEqual(len(line), 118, f"line {number}")

    def test_generated_formula_has_valid_ruby_syntax(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        syntax = subprocess.run(["ruby", "-c", str(self.output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertIn("Syntax OK", syntax.stdout)

    def test_modified_archive_hash_is_rejected(self):
        with next(self.dist.glob("*.tar.gz")).open("ab") as file:
            file.write(b"changed")
        self.failure("checksum mismatch")

    def test_version_injection_is_rejected(self):
        self.version.write_text('1.2.3\"; system(\"bad\")\n')
        self.failure("VERSION")

    def test_semver_build_metadata_is_preserved(self):
        self.archives("1.2.3-rc.1+build.01")
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('version "1.2.3-rc.1+build.01"', self.output.read_text())
        self.assertIn('/v1.2.3-rc.1+build.01/aws-sso-profile-sync_1.2.3-rc.1+build.01_', self.output.read_text())

    def test_noncanonical_prerelease_is_rejected(self):
        self.version.write_text("1.2.3-01\n")
        self.failure("VERSION")

    def test_checksum_name_injection_is_rejected(self):
        with (self.dist / "SHA256SUMS").open("a") as file:
            file.write("a" * 64 + '  ../../evil\".tar.gz\n')
        self.failure("unexpected archive")

    def test_archive_version_mismatch_is_rejected(self):
        self.version.write_text("2.0.0\n")
        self.failure("unexpected archive")

    def test_metadata_mismatch_is_rejected(self):
        path = next(self.dist.glob("*linux_arm64.tar.gz"))
        with tarfile.open(path, "w:gz") as archive:
            data = json.dumps({"version": "1.2.3-rc.1", "target": "linux/amd64"}).encode()
            info = tarfile.TarInfo(path.name[:-7] + "/BUILD-METADATA.json")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.checksums()
        self.failure("metadata mismatch")

    def test_symlink_archive_is_rejected(self):
        path = next(self.dist.glob("*.tar.gz"))
        copy = self.root / "outside.tar.gz"
        path.rename(copy)
        path.symlink_to(copy)
        self.failure("regular file")

    def test_duplicate_checksum_is_rejected(self):
        sums = self.dist / "SHA256SUMS"
        sums.write_text(sums.read_text() + sums.read_text().splitlines()[0] + "\n")
        self.failure("duplicate")


if __name__ == "__main__":
    unittest.main()
