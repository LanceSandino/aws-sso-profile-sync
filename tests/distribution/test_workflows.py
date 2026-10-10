"""Guard release authorization boundaries without executing GitHub mutations."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def job(text, name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [\w-]+:\n|\Z)", text, re.M | re.S)
    if not match:
        raise ValueError("Required workflow job is missing: " + name)
    return match.group(1)


def release_policy(release, validation):
    events = re.search(r"^on:\n(.*?)(?=^\S|\Z)", release, re.M | re.S)
    if not events or re.findall(r"^  ([\w_]+):", events.group(1), re.M) != ["workflow_dispatch"]:
        raise ValueError("Release must be manually dispatched only")
    eligibility = job(release, "eligibility")
    draft = job(release, "draft")
    required = job(release, "validation")
    if 'test "$DEFAULT_BRANCH" = main' not in eligibility or 'test "$GITHUB_REF" = refs/heads/main' not in eligibility:
        raise ValueError("Both main-branch checks are required")
    if "scripts/release.py gate" not in eligibility or "scripts/release.py gate" not in draft:
        raise ValueError("Acceptance must be checked before validation and before writes")
    dependencies = re.search(r"^    needs: \[([^\]]+)\]", draft, re.M)
    if not dependencies or {part.strip() for part in dependencies.group(1).split(",")} != {"eligibility", "validation"}:
        raise ValueError("Writes must depend on acceptance and full validation")
    if "uses: ./.github/workflows/validate.yml" not in required:
        raise ValueError("Release must reuse the complete validation workflow")
    if "environment: release" not in draft or release.count("contents: write") != 1 or "contents: write" not in draft:
        raise ValueError("Only the protected release job may have write permission")
    if "current_main" not in draft or 'test "$current_main" = "$GITHUB_SHA"' not in draft:
        raise ValueError("Source branch must remain unchanged before tag creation")
    commands = re.sub(r"\\\n\s*", " ", draft)
    create = re.search(r"gh release create .*", commands)
    if not create or not re.search(r"(?:^|\s)--draft(?:\s|$)", create.group(0)):
        raise ValueError("Release creation must remain draft-only")
    if re.search(r"gh release edit|--draft[= ]false|gh api[^\n]*--method (?:PATCH|PUT)[^\n]*/releases", draft):
        raise ValueError("Automatic publication is forbidden")
    if "scripts/homebrew.py" not in draft or "scripts/check_public.py" not in draft:
        raise ValueError("Archives and Homebrew handoff need validation before writing")
    native = job(validation, "unit")
    targets = set(re.findall(r"^            target: (\S+)", native, re.M))
    if targets != {"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}:
        raise ValueError("All four native targets are required")
    if "NATIVE_OFFLINE_SMOKE_PASS" not in draft or "SHA256SUMS-$TARGET_ID" not in native:
        raise ValueError("Native artifact execution and separate checksum manifests are required")
    integration = job(validation, "floci")
    if "go test -tags integration" not in integration or "range(1,11)" not in integration or "and not skips" not in integration:
        raise ValueError("All real Floci cases must execute without skips")
    minimum = job(validation, "minimum-go")
    if "GOTOOLCHAIN: local" not in minimum or "go-version: '1.25.x'" not in minimum:
        raise ValueError("The minimum Go compilation job must not upgrade toolchains")
    for action in re.findall(r"uses: (actions/[^\s]+)", release + validation):
        if not re.fullmatch(r"actions/[\w-]+@[0-9a-f]{40}", action):
            raise ValueError("Official actions must be pinned to immutable commits")


class WorkflowBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (ROOT / ".github/workflows/release.yml").read_text()
        cls.validation = (ROOT / ".github/workflows/validate.yml").read_text()

    def test_release_requires_all_authorization_boundaries(self):
        release_policy(self.release, self.validation)

    def test_branch_gate_cannot_be_removed(self):
        for guard in ('test "$DEFAULT_BRANCH" = main', 'test "$GITHUB_REF" = refs/heads/main'):
            with self.subTest(guard=guard), self.assertRaises(ValueError):
                release_policy(self.release.replace(guard, "true"), self.validation)

    def test_pending_acceptance_cannot_be_bypassed_at_either_gate(self):
        for index in (0, self.release.rfind("python3 scripts/release.py gate")):
            changed = self.release[:index] + self.release[index:].replace("python3 scripts/release.py gate", "true", 1)
            # The draft rechecks twice; remove all its checks for the second mutation.
            if index:
                start = self.release.index("  draft:\n")
                changed = self.release[:start] + self.release[start:].replace("python3 scripts/release.py gate", "true")
            with self.subTest(index=index), self.assertRaises(ValueError):
                release_policy(changed, self.validation)

    def test_write_job_cannot_skip_owner_environment_or_tests(self):
        for original, replacement in (("environment: release", "environment: unprotected"),
                                      ("needs: [eligibility, validation]", "needs: [eligibility]")):
            with self.subTest(boundary=original), self.assertRaises(ValueError):
                release_policy(self.release.replace(original, replacement), self.validation)

    def test_auto_trigger_or_publication_is_rejected(self):
        for changed in (self.release.replace("  workflow_dispatch:", "  push:"),
                        self.release.replace("--verify-tag --draft", "--verify-tag"),
                        self.release.replace("--verify-tag --draft", "--verify-tag --draft=false")):
            with self.subTest(), self.assertRaises(ValueError):
                release_policy(changed, self.validation)

    def test_native_or_floci_validation_cannot_be_dropped(self):
        for changed in (self.validation.replace("target: linux/arm64", "target: linux/amd64"),
                        self.validation.replace("  floci:\n", "  removed-integration:\n"),
                        self.validation.replace("and not skips", "or skips")):
            with self.subTest(), self.assertRaises(ValueError):
                release_policy(self.release, changed)

    def test_mutable_action_tag_is_rejected(self):
        changed = re.sub(r"actions/download-artifact@[0-9a-f]{40}", "actions/download-artifact@v8", self.release)
        with self.assertRaises(ValueError):
            release_policy(changed, self.validation)


if __name__ == "__main__":
    unittest.main()
