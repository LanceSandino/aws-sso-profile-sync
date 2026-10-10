#!/usr/bin/env python3
"""Inspect exact Git trees, new history and package contents without printing secrets.

This is a publication gate, not a claim that pattern matching detects every secret.
Only Git and the Python standard library are required; no network or AWS is used.
"""
import argparse
import pathlib
import re
import subprocess
import tarfile

PRIVATE_ROOTS = {"docs/spec", "quality", ".aws", ".codex", ".claude"}
PRIVATE_FILES = {"AGENTS.md", "HANDOFF.md", "CHANGES.md", "DECISIONS.md", "credentials", "token.json", ".env"}
RULES = {
    "AWS access key": re.compile(rb"\b(?:AK" + rb"IA|ASIA)[A-Z0-9]{16}\b"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_" + rb"[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE" + rb" KEY-----"),
    "signed private document": re.compile(rb"https?://[^\s\"']+[?&](?:sig|signature)=[A-Za-z0-9%]+"),
    "machine home": re.compile(rb"/(?:Users|home)/([A-Za-z0-9._-]+)/"),
}
GENERIC_USERS = {b"runner", b"user", b"username", b"test", b"example", b"ubuntu", b"alice", b"bob"}


def scan(name, data):
    """Return (path, rule) findings; never include matching values."""
    path = pathlib.PurePosixPath(name)
    findings = []
    private_root = any(tuple(path.parts[offset:offset + len(parts)]) == parts
                       for parts in (pathlib.PurePosixPath(root).parts for root in PRIVATE_ROOTS)
                       for offset in range(len(path.parts)))
    if path.name in PRIVATE_FILES or private_root:
        findings.append((name, "private file"))
    if path.name.startswith(".env.") or path.suffix in {".pem", ".key", ".pyc", ".log"} or "__pycache__" in path.parts:
        findings.append((name, "private or generated artifact"))
    for rule, pattern in RULES.items():
        for match in pattern.finditer(data):
            if rule == "machine home" and (match.group(1) in GENERIC_USERS or len(match.group(1)) <= 2):
                continue
            findings.append((name, rule))
            break
    return findings


def scan_archive(archive):
    findings = []
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                findings.append((member.name, "unsafe archive member"))
                continue
            if member.isfile():
                if member.size > 100 * 1024 * 1024:
                    findings.append((member.name, "oversized archive member"))
                else:
                    findings.extend(scan(member.name, source.extractfile(member).read()))
    return findings


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def scan_tree(root, revision):
    findings = []
    for row in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if not row:
            continue
        metadata, raw_name = row.split(b"\t", 1)
        mode, kind, sha = metadata.split()
        name = raw_name.decode("utf-8")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            findings.append((name, "unreviewed link or submodule"))
        else:
            findings.extend(scan(name, git(root, "cat-file", "blob", sha.decode())))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--base", help="Scan every newly reachable commit after this already-public ancestor")
    parser.add_argument("--archives", type=pathlib.Path, help="Also scan every .tar.gz package in this directory")
    args = parser.parse_args()
    findings = scan_tree(args.root, args.rev)
    revisions = []
    if args.base:
        git(args.root, "merge-base", "--is-ancestor", args.base, args.rev)
        revisions = git(args.root, "rev-list", f"{args.base}..{args.rev}").decode().splitlines()
        for revision in revisions:
            findings.extend(scan_tree(args.root, revision))
            findings.extend(scan("commit message", git(args.root, "show", "-s", "--format=%B", revision)))
    if args.archives:
        archives = sorted(args.archives.glob("*.tar.gz"))
        if not archives:
            raise SystemExit("No package archives selected")
        for archive in archives:
            findings.extend(scan_archive(archive))
    for name, rule in sorted(set(findings)):
        print(f"FAIL {name}: {rule}")
    if findings:
        raise SystemExit(1)
    print(f"Public content gate passed; exact tree and {len(revisions)} new history commits checked")


if __name__ == "__main__":
    main()
