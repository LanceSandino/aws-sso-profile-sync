"""Regression tests for the public tree and artifact privacy gate."""
import importlib.util
import io
import pathlib
import os
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("public_check", ROOT / "scripts/check_public.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PublicSafety(unittest.TestCase):
    def test_private_files_and_machine_paths_rejected(self):
        self.assertTrue(checker.scan("docs/spec/README.md", b"private"))
        self.assertTrue(checker.scan("docs/install.md", b"/" + b"Users" + b"/real-person/private/file"))
        self.assertTrue(checker.scan("state/.aws/credentials", b"synthetic"))
        self.assertTrue(checker.scan("state/.aws/config", b"synthetic"))
        self.assertTrue(checker.scan("state/token.json", b"private"))

    def test_tokens_redacted_and_synthetic_fixtures_allowed(self):
        value = ("ghp_" + "A" * 40).encode()
        findings = checker.scan("README.md", value)
        self.assertTrue(findings)
        self.assertNotIn(value.decode(), repr(findings))
        self.assertFalse(checker.scan("tests/example_test.go", b"test-only /home/runner/work/project"))

    def test_archive_traversal_links_and_binary_paths_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = pathlib.Path(directory) / "candidate.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                for name, value in [("../outside", b"x"), ("pkg/binary", b"\x00/" + b"Users" + b"/real-person/build/main.go\x00")]:
                    entry = tarfile.TarInfo(name); entry.size = len(value)
                    output.addfile(entry, io.BytesIO(value))
                entry = tarfile.TarInfo("pkg/link"); entry.type = tarfile.SYMTYPE; entry.linkname = "/outside"
                output.addfile(entry)
            findings = checker.scan_archive(archive)
            self.assertGreaterEqual(len(findings), 3)

    def test_deleted_private_file_still_blocks_new_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment = dict(os.environ, GIT_AUTHOR_NAME="test-only", GIT_AUTHOR_EMAIL="test@example.invalid", GIT_COMMITTER_NAME="test-only", GIT_COMMITTER_EMAIL="test@example.invalid")
            def git(*args):
                return subprocess.run(["git", "-C", directory, *args], env=environment, capture_output=True, check=True, timeout=10).stdout.decode().strip()
            git("init", "-q")
            (root / "README.md").write_text("public")
            git("add", "."); git("commit", "-qm", "Public baseline")
            baseline = git("rev-parse", "HEAD")
            (root / "HANDOFF.md").write_text("private")
            git("add", "."); git("commit", "-qm", "Add private record")
            git("rm", "HANDOFF.md"); git("commit", "-qm", "Remove private record")
            self.assertFalse(checker.scan_tree(root, "HEAD"))
            result = subprocess.run(["python3", str(ROOT / "scripts/check_public.py"), "--root", directory, "--base", baseline], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private file", result.stdout)


if __name__ == "__main__":
    unittest.main()
