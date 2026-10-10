"""Release metadata regressions use synthetic temporary repositories only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release.py"
R_CASES = [f"R{i:02d}" for i in range(1, 10)]

class ReleaseSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aws-sso-release-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.version("0.1.0-rc.1")
        (self.root / "main.go").write_text("package main\nfunc main() {}\n")
        self.run_helper("check", "--write", success=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Synthetic Release Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Synthetic baseline"], check=True)

    def version(self, value):
        (self.root / "VERSION").write_text(value + "\n")

    def run_helper(self, command, *args, success=None):
        result = subprocess.run(["python3", str(SCRIPT), command, "--root", str(self.root), *args], capture_output=True, text=True, timeout=10)
        if success is not None:
            self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def acceptance(self):
        record = {"schema_version": 1, "status": "PASS", "version": "0.1.0-rc.1", "source_fingerprint": self.run_helper("fingerprint", success=True).stdout.strip(), "real_aws_acceptance": {case: "PASS" for case in R_CASES}}
        target = self.root / ".github" / "release-acceptance.json"
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(record))
        return target, record

    def test_single_source_generation_and_stale_default(self):
        self.assertEqual(self.run_helper("version", success=True).stdout, "0.1.0-rc.1\n")
        self.run_helper("check", success=True)
        self.version("0.2.0")
        self.run_helper("check", success=False)
        self.run_helper("check", "--write", success=True)
        self.run_helper("check", success=True)
        self.assertIn('var Version = "0.2.0"', (self.root / "internal/cli/version.go").read_text())
        self.run_helper("version", "--expect", "0.1.0-rc.1", success=False)
        self.run_helper("version", "--expect", "0.2.0", success=True)

    def test_strict_semver_prerelease_and_build(self):
        for value in ["0.0.0", "1.2.3", "0.1.0-rc.1", "1.2.3-alpha.0", "1.2.3-0", "1.2.3+build.001", "1.2.3-rc.1+build-0"]:
            with self.subTest(valid=value):
                self.version(value)
                self.run_helper("version", success=True)
        for value in ["v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-alpha..1", "1.2.3-", "1.2.3+", "1.2.3-α", "1.2.3 ", "1.2.3\n2.0.0"]:
            with self.subTest(invalid=value):
                self.version(value)
                self.run_helper("version", success=False)

    def test_fingerprint_binds_tracked_content_modes_and_paths(self):
        first = self.run_helper("fingerprint", success=True).stdout
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}\n$")
        (self.root / "untracked.txt").write_text("scratch")
        self.assertEqual(first, self.run_helper("fingerprint", success=True).stdout)
        main = self.root / "main.go"
        main.write_text("package main\nfunc main() { println(1) }\n")
        self.assertNotEqual(first, self.run_helper("fingerprint", success=True).stdout)
        main.write_text("package main\nfunc main() {}\n")
        main.chmod(0o755)
        self.assertNotEqual(first, self.run_helper("fingerprint", success=True).stdout)
        main.chmod(0o644)
        self.assertEqual(first, self.run_helper("fingerprint", success=True).stdout)
        subprocess.run(["git", "-C", str(self.root), "mv", "main.go", "renamed.go"], check=True)
        self.assertNotEqual(first, self.run_helper("fingerprint", success=True).stdout)

    def test_fingerprint_ignores_git_index_blob_order(self):
        main = self.root / "main.go"
        for value in range(16):
            main.write_text(f"package main\nfunc main() {{ println({value}) }}\n")
            before_staging = self.run_helper("fingerprint", success=True).stdout
            subprocess.run(["git", "-C", str(self.root), "add", "main.go"], check=True)
            self.assertEqual(before_staging, self.run_helper("fingerprint", success=True).stdout)

    def test_acceptance_exclusion_does_not_hide_other_changes(self):
        first = self.run_helper("fingerprint", success=True).stdout
        target, _ = self.acceptance()
        subprocess.run(["git", "-C", str(self.root), "add", ".github/release-acceptance.json"], check=True)
        self.assertEqual(first, self.run_helper("fingerprint", success=True).stdout)
        target.write_text("different acceptance content")
        self.assertEqual(first, self.run_helper("fingerprint", success=True).stdout)
        other = target.parent / "workflow.yml"
        other.write_text("workflow")
        subprocess.run(["git", "-C", str(self.root), "add", ".github/workflow.yml"], check=True)
        self.assertNotEqual(first, self.run_helper("fingerprint", success=True).stdout)

    def test_gate_requires_all_nine_real_acceptance_passes(self):
        self.run_helper("gate", success=False)
        target, record = self.acceptance()
        self.run_helper("gate", success=True)
        for case in R_CASES:
            for status in ["NOT_RUN", "FAIL", "BLOCKED", "N_A", None]:
                record["real_aws_acceptance"][case] = status
                target.write_text(json.dumps(record))
                self.run_helper("gate", success=False)
            del record["real_aws_acceptance"][case]
            target.write_text(json.dumps(record))
            self.run_helper("gate", success=False)
            record["real_aws_acceptance"][case] = "PASS"
        target.write_text(json.dumps(record))
        self.run_helper("gate", success=True)

    def test_gate_rejects_pending_stale_invalid_or_duplicate_records(self):
        target, valid = self.acceptance()
        for key, value in [("status", "PENDING"), ("version", "0.2.0"), ("source_fingerprint", "sha256:" + "0" * 64), ("schema_version", True), ("real_aws_acceptance", {**valid["real_aws_acceptance"], "R10": "PASS"})]:
            record = {**valid, key: value}
            target.write_text(json.dumps(record))
            self.run_helper("gate", success=False)
        for body in ["[]", "malformed", '{"schema_version":1,"schema_version":1}']:
            target.write_text(body)
            self.run_helper("gate", success=False)
        target.write_text(json.dumps(valid))
        self.version("0.2.0")
        self.run_helper("gate", success=False)

    def test_untracked_release_inputs_and_dirty_tracked_gate_fail_closed(self):
        first = self.run_helper("fingerprint", success=True).stdout
        for name in ["unexpected.go", "LICENSE", "scripts/new-helper.py", "docs/new-guide.md", "go.work", "go.work.sum", "packaging/formula.rb.in", "vendor/modules.txt", "unexpected.syso"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("untracked input")
            self.run_helper("fingerprint", success=False)
            path.unlink()
        self.assertEqual(first, self.run_helper("fingerprint", success=True).stdout)
        (self.root / ".gitignore").write_text("ignored.go\n")
        subprocess.run(["git", "-C", str(self.root), "add", ".gitignore"], check=True)
        ignored = self.root / "ignored.go"
        ignored.write_text("package main\n")
        self.run_helper("fingerprint", success=False)
        ignored.unlink()
        target, record = self.acceptance()
        (self.root / "main.go").write_text("package main\nfunc main() { println(5) }\n")
        record["source_fingerprint"] = self.run_helper("fingerprint", success=True).stdout.strip()
        target.write_text(json.dumps(record))
        self.run_helper("gate", success=False)

    def test_missing_tree_files_symlinks_and_non_repository_fail_closed(self):
        (self.root / "main.go").unlink()
        self.run_helper("fingerprint", success=False)
        (self.root / "main.go").symlink_to("outside")
        self.run_helper("fingerprint", success=False)
        with tempfile.TemporaryDirectory() as outside:
            result = subprocess.run(["python3", str(SCRIPT), "fingerprint", "--root", outside], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_gate_requires_committed_source_baseline(self):
        target, record = self.acceptance()
        self.run_helper("gate", success=True)
        (self.root / "main.go").write_text("package main\nfunc main() { println(9) }\n")
        subprocess.run(["git", "-C", str(self.root), "add", "main.go"], check=True)
        record["source_fingerprint"] = self.run_helper("fingerprint", success=True).stdout.strip()
        target.write_text(json.dumps(record))
        self.run_helper("gate", success=False)
        subprocess.run(["git", "-C", str(self.root), "update-ref", "-d", "HEAD"], check=True)
        self.run_helper("gate", success=False)

if __name__ == "__main__":
    unittest.main()
