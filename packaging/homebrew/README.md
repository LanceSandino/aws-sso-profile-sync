# Homebrew packaging

AWS SSO Profile Sync 2.0.1 is published and available from the public shared
[Homebrew tap](https://github.com/LanceSandino/homebrew-tap):

```sh
brew install LanceSandino/tap/aws-sso-profile-sync
```

The instructions below are for maintainers generating a formula for a future
release. Users can follow [installation](../../docs/install.md).

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

The release workflow uploads the generated formula as a `homebrew-handoff`
workflow artifact; the draft contains the four archives and `SHA256SUMS`.
A draft does not make its download URLs publicly usable.
After publishing the accepted release, open a reviewable PR containing
the generated formula in `LanceSandino/homebrew-tap/Formula/`. Verify the PR's
hashes against the exact published assets and run the tap checks before merging.
Formula generation does not publish a release or change the tap.

`tap/` preserves the original bootstrap snapshot. The standalone tap has its own
lifecycle and later CI fixes; its current README and validation files are the
maintenance authority. Candidate CI validates freshly built archives through a
loopback server. Published CI independently verifies public release assets and
installs the actual formula on all four targets. Its offline test uses disposable
HOME and explicit AWS paths. These checks passed for published 2.0.1; they must run
again for each formula update. Neither workflow automatically publishes releases
or updates formulas.
