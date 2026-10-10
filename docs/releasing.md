# Preparing an approved release

`2.0.0-rc.1` is an unpublished candidate. Local emulator validation is separate from real AWS IAM Identity Center and AWS CLI acceptance, which remains pending. The release workflow starts only by manual dispatch on the default `main` branch. It never automatically publishes a release.

## Version and validation

`VERSION` is the single SemVer source. A Git tag uses the same value prefixed with `v`, for example `v2.0.0-rc.1`. For a later version, update `VERSION` and `CHANGELOG.md`, then regenerate the compiled version:

```bash
python3 scripts/release.py check --write
python3 scripts/release.py check
python3 scripts/release.py version
```

Commit the reviewed source before recording acceptance. Normal validation requires four native runner jobs (`linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`), minimum Go 1.25 compilation, and the separate pinned Floci integration suite. Every native job builds, runs the test and coverage gates, packages its target, checks archive privacy, and installs and executes its own archive. Cross-compilation alone does not certify a target. Hosted workflow execution is still required before a release; declarations and local smoke results do not replace it.

Version 2 identifies the replacement of the previously unversioned tool. Explicit login and collision-resistant profile naming change its public contracts; this does not imply a historical `1.0.0` tag. Use PATCH for compatible fixes, MINOR for compatible additions and MAJOR for breaking changes. Use `-rc.N` for candidates and remove the prerelease suffix only after final acceptance. Validation requires the first versioned changelog entry to match `VERSION` exactly once. Record user-visible changes under Added, Fixed and Improved, with explicit breaking-change notes.

The runner labels are listed in the [official GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Workflow actions use verified immutable official action revisions.

## Real AWS acceptance and source binding

The owner must complete the [manual AWS acceptance procedure](manual-aws-acceptance.md) on an authorized machine. Do not replace real acceptance with emulator results. Keep tokens, credentials and personal configuration out of release records.

`.github/release-acceptance.json` defaults to `PENDING`, with every real acceptance case `R01` through `R09` marked `NOT_RUN`. Only after observing all nine cases pass for the intended version and source, record their `PASS` values, set the top-level status to `PASS`, and record the exact source fingerprint:

```bash
python3 scripts/release.py fingerprint
python3 scripts/release.py gate
```

Copy the fingerprint output into `source_fingerprint` and the exact `VERSION` into `version`. The fingerprint covers tracked source contents and modes, excluding only the acceptance JSON itself so the record can bind to its source. Missing cases, pending values, malformed records, a version mismatch or any subsequent source change makes the gate fail. Acceptance is an owner attestation backed by actual operator evidence; the script validates its binding and completeness, not the truth of external test results.

## Owner approval and draft creation

Configure a GitHub environment named `release` before dispatch. Require the repository owner's review, disable administrator bypass, and restrict deployment to the protected default `main` branch. A sole owner who dispatches the workflow must be allowed to approve it; review restrictions must match that operating model. Set `RELEASE_TAGGER_NAME` and `RELEASE_TAGGER_EMAIL` in that environment to the approved contributor identity. Missing values cause the write job to fail. Environment protection is repository configuration and must be verified by the owner; the YAML cannot create a required-reviewer policy.

Merge reviewed source through the repository's normal owner-controlled process. On the resulting default `main`, manually dispatch **Prepare approved draft release**. No dispatch input overrides the version. The workflow:

1. Refuses another branch or pending/stale real AWS acceptance.
2. Re-runs all native, minimum-toolchain and Floci validation.
3. Waits for the protected `release` environment's owner approval before its write job.
4. Rechecks acceptance, four native archive checksums and archive privacy, then preserves a validated `homebrew-handoff` formula artifact for later review. It verifies that `main` still points to the reviewed source commit before creating the tag.
5. Creates an annotated `v<VERSION>` tag, then a **draft** GitHub release with four archives and combined `SHA256SUMS`. Prerelease SemVer values also set the draft's prerelease flag.

The workflow does not move or replace an existing tag, overwrite a release, merge a branch or publish the draft. If it fails after creating the tag, inspect the repository state before retrying; do not force-update the tag to hide a partial operation.

## Review, publication and Homebrew handoff

Download the draft assets, compare the four expected OS/architecture names and verify the combined checksums. Review the changelog, licensing notices, version output and installation instructions. Each archive contains its build metadata and the installer checks its native target before replacing any executable. Test installation with a disposable HOME and explicit configuration paths; preserve rollback backups.

Publishing the draft is a separate manual owner action after that review. A GitHub draft is not a public release, and no workflow automatically changes it to published. Record the published tag and immutable asset URLs only after the owner publishes.

A later Homebrew handoff must use that published version and the corresponding Darwin/Linux Intel/ARM archive URLs and SHA-256 values. Update a formula in the owner-selected tap only with separate authorization, verify installation and version reporting on the supported machines, and run offline diagnostics with an isolated HOME. This repository does not automatically update Homebrew, a package registry or `@latest` source installation.
