# Homebrew release preparation

`scripts/homebrew.py` produces a formula from `VERSION`, all four local release
archives and their actual `SHA256SUMS`. It verifies every digest and the embedded
archive version/target before writing deterministic Ruby. GitHub download URLs
are fixed to this repository's `v<VERSION>` release. No placeholder checksums or
arbitrary remote locations are accepted.
The formula preserves the exact SemVer when Homebrew's URL parser would truncate
prerelease or build metadata, and avoids a redundant override when detection is exact.

```sh
/bin/bash -n scripts/package.sh
VERSION="$(cat VERSION)" TARGETS='darwin/amd64 darwin/arm64 linux/amd64 linux/arm64' /bin/bash scripts/package.sh
python3 scripts/homebrew.py --version-file VERSION --dist-dir "dist/$(cat VERSION)" \
  --output "dist/$(cat VERSION)/aws-sso-profile-sync.rb"
python3 -m unittest discover -s tests/distribution -p test_homebrew.py
```

The release workflow can attach this formula to the draft alongside matching
archives and checksums. A draft does not make its download URLs publicly usable.
After the owner publishes the accepted release, open a reviewable PR containing
the generated formula in `LanceSandino/homebrew-tap/Formula/`. Verify the PR's
hashes against the exact published assets and run the tap checks before merging.
Formula generation does not publish a release or change the tap.

`tap/` is the standalone future tap scaffold. Its CI builds candidate archives
from an explicit app source revision, audits the generated public formula, then
installs a copy using only a loopback HTTP server serving those local archives.
The default source branch is `feature/release-review`; a dispatch or repository
variable can select another reviewable revision. Native Homebrew checks both the
release version and SemVer build metadata before installation.
That tests packaging before public assets exist. It does not certify real AWS
or public download availability. The formula's own test runs only `--version`
and offline `doctor` with disposable HOME and explicit AWS file paths.

No public Homebrew installation is available until the owner publishes the
release assets and merges the corresponding tap formula.
