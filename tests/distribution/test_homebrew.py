"""Verify deterministic Homebrew output from isolated synthetic release archives."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/homebrew.py"
TARGETS = (("darwin", "amd64"), ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"))


def homebrew_workflow_policy(text):
    steps = re.split(r"^      - ", text, flags=re.M)[1:]
    setups = [i for i, step in enumerate(steps) if "uses: Homebrew/actions/setup-homebrew@" in step]
    apps = [i for i, step in enumerate(steps) if "repository: LanceSandino/aws-sso-profile-sync" in step]
    checkouts = [i for i, step in enumerate(steps) if "uses: actions/checkout@" in step]
    if len(setups) != 1 or len(apps) != 1 or len(checkouts) != 2:
        raise ValueError("Required setup and checkout steps are missing")
    setup = steps[setups[0]]
    if not checkouts[0] < setups[0] < apps[0]:
        raise ValueError("Homebrew setup must precede the application checkout")
    if not re.search(r"^          token: \$\{\{ github\.token \}\}$", setup, re.M):
        raise ValueError("Private tap setup needs the ephemeral repository token")
    if not re.search(r"^          stable: true$", setup, re.M):
        raise ValueError("Setup must select stable Homebrew")
    limit = re.search(r"^        timeout-minutes: (\d+)$", setup, re.M)
    if not limit or not 1 <= int(limit[1]) <= 5:
        raise ValueError("Homebrew setup needs a five-minute-or-shorter bound")
    for index in checkouts:
        if not re.search(r"^          persist-credentials: false$", steps[index], re.M):
            raise ValueError("Checkout credentials must not persist")
    if not re.search(r"^          GIT_CONFIG_GLOBAL: \$\{\{ runner\.temp \}\}/application-checkout\.gitconfig$",
                     steps[apps[0]], re.M):
        raise ValueError("Application checkout must isolate setup's global Git authentication header")
    if "brew tap --custom-remote" in text:
        raise ValueError("Setup already owns the canonical tap remote")


class HomebrewWorkflow(unittest.TestCase):
    def test_setup_is_bounded_authenticated_and_preserves_app_checkout(self):
        workflow = (ROOT / "packaging/homebrew/tap/.github/workflows/candidate.yml").read_text()
        homebrew_workflow_policy(workflow)

    def test_setup_rejects_auth_timeout_order_and_checkout_leaks(self):
        workflow = (ROOT / "packaging/homebrew/tap/.github/workflows/candidate.yml").read_text()
        for old, new in (("token: ${{ github.token }}", "token: ''"),
                         ("timeout-minutes: 5", "timeout-minutes: 99"),
                         ("stable: true", "stable: false"),
                         ("persist-credentials: false", "persist-credentials: true"),
                         ("GIT_CONFIG_GLOBAL:", "REMOVED_GIT_CONFIG_GLOBAL:"),
                         ("Homebrew/actions/setup-homebrew@", "Removed/actions/setup-homebrew@")):
            with self.subTest(boundary=old), self.assertRaises(ValueError):
                homebrew_workflow_policy(workflow.replace(old, new))
        before, *steps = re.split(r"^      - ", workflow, flags=re.M)
        setup = next(i for i, step in enumerate(steps) if "uses: Homebrew/actions/setup-homebrew@" in step)
        app = next(i for i, step in enumerate(steps) if "repository: LanceSandino/aws-sso-profile-sync" in step)
        steps[setup], steps[app] = steps[app], steps[setup]
        with self.assertRaises(ValueError):
            homebrew_workflow_policy(before + "".join("      - " + step for step in steps))

    def test_style_audit_copy_handles_samefile_and_separate_tap(self):
        workflow = (ROOT / "packaging/homebrew/tap/.github/workflows/candidate.yml").read_text()
        step = workflow.split("      - name: Style and audit the exact generated public formula\n", 1)[1].split("      - name:", 1)[0]
        script = "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())
        for layout in ("same", "symlink", "separate"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workspace = root / "workspace"
                (workspace / "Formula").mkdir(parents=True)
                source = workspace / "Formula/aws-sso-profile-sync.rb"
                source.write_bytes(b"synthetic formula\n")
                os.utime(source, (1600000000, 1600000000))
                if layout == "same":
                    tap = workspace
                elif layout == "symlink":
                    tap = root / "tap-link"
                    tap.symlink_to(workspace, target_is_directory=True)
                else:
                    tap = root / "tap"
                    tap.mkdir()
                bin_dir = root / "bin"
                bin_dir.mkdir()
                brew = bin_dir / "brew"
                brew.write_text('#!/bin/bash\nset -euo pipefail\ncase "$1" in\n'
                                '--repository) printf "%s\\n" "$SYNTHETIC_TAP_ROOT" ;;\n'
                                'command) exit 1 ;;\n'
                                'style|audit) printf "%s\\n" "$1" >> "$SYNTHETIC_BREW_LOG" ;;\n'
                                '*) exit 99 ;;\nesac\n')
                brew.chmod(0o755)
                syntax = subprocess.run(["/bin/bash", "-n", str(brew)], capture_output=True, text=True, timeout=5)
                self.assertEqual(syntax.returncode, 0, syntax.stderr)
                log = root / "brew.log"
                env = {"PATH": str(bin_dir) + ":/usr/bin:/bin", "HOME": str(root),
                       "SYNTHETIC_TAP_ROOT": str(tap), "SYNTHETIC_BREW_LOG": str(log)}
                syntax = subprocess.run(["/bin/bash", "-n"], input=script, env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(syntax.returncode, 0, syntax.stderr)
                for _ in range(2):
                    result = subprocess.run(["/bin/bash", "-c", script], cwd=workspace, env=env,
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((tap / "Formula/aws-sso-profile-sync.rb").read_bytes(), source.read_bytes())
                self.assertEqual(source.stat().st_mtime_ns, 1600000000000000000)
                self.assertEqual(log.read_text().splitlines(), ["style", "audit", "style", "audit"])

    def candidate_readiness_script(self):
        workflow = (ROOT / "packaging/homebrew/tap/.github/workflows/candidate.yml").read_text()
        match = re.search(r"          python3 - \"\$port_file\"(?: \"\$server_pid\")? <<'PY'\n(.*?)          PY", workflow, re.S)
        self.assertIsNotNone(match, "bounded candidate readiness script missing")
        return "\n".join(line[10:] for line in match[1].splitlines())

    def test_candidate_readiness_accepts_startup_after_five_seconds(self):
        script = self.candidate_readiness_script()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "port"
            timer = threading.Timer(5.2, path.write_text, args=("12345",))
            timer.start()
            try:
                env = {"PATH": os.environ["PATH"], "HOME": directory}
                result = subprocess.run([sys.executable, "-c", script, str(path), str(os.getpid())],
                                        env=env, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.read_text(), "12345")
            finally:
                timer.cancel()
                timer.join(timeout=1)

    def test_candidate_readiness_fails_fast_if_owned_server_exits(self):
        script = self.candidate_readiness_script()
        with tempfile.TemporaryDirectory() as directory:
            env = {"PATH": os.environ["PATH"], "HOME": directory}
            server = subprocess.Popen([sys.executable, "-c", "pass"], env=env)
            server.wait(timeout=2)
            result = subprocess.run([sys.executable, "-c", script, str(Path(directory) / "port"), str(server.pid)],
                                    env=env, capture_output=True, text=True, timeout=2)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Candidate HTTP server exited before readiness", result.stderr)

    def test_candidate_readiness_has_thirty_second_deadline(self):
        script = self.candidate_readiness_script()
        with tempfile.TemporaryDirectory() as directory:
            args = ["candidate-readiness", str(Path(directory) / "port"), str(os.getpid())]
            with patch.object(sys, "argv", args), patch("time.monotonic", side_effect=[100, 129.9, 130]), patch("time.sleep") as sleep:
                with self.assertRaisesRegex(SystemExit, "Candidate HTTP server did not start within 30 seconds"):
                    exec(compile(script, "<candidate-readiness>", "exec"), {})
                sleep.assert_called_once_with(0.1)

    def test_scoped_global_git_config_prevents_duplicate_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".gitconfig").write_text('[http "https://github.com/"]\n\textraheader = synthetic-global\n')
            isolated = home / "application-checkout.gitconfig"
            isolated.write_text("")
            env = {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"}
            args = ["git", "-c", "http.https://github.com/.extraheader=synthetic-checkout",
                    "config", "--get-all", "http.https://github.com/.extraheader"]
            inherited = subprocess.run(args, env=env, capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(inherited.stdout.splitlines(), ["synthetic-global", "synthetic-checkout"])
            env["GIT_CONFIG_GLOBAL"] = str(isolated)
            scoped = subprocess.run(args, env=env, capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(scoped.stdout.splitlines(), ["synthetic-checkout"])
            self.assertIn("synthetic-global", (home / ".gitconfig").read_text())


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

    def test_version_override_only_when_native_detection_differs(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('version "1.2.3-rc.1" if version.to_s != "1.2.3-rc.1"', self.output.read_text())

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
