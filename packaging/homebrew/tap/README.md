# Lance Sandino's Homebrew tap

Install AWS SSO Profile Sync:

```sh
brew install LanceSandino/tap/aws-sso-profile-sync
brew test LanceSandino/tap/aws-sso-profile-sync
```

The formula uses the application's published release archives and exact SHA256
checksums. AWS SSO Profile Sync is a CLI; no GUI, service or AWS CLI dependency is
installed. Its formula test uses disposable HOME, explicit AWS file paths and only
offline `--version` and `doctor`. Real AWS acceptance is a separate owner procedure
documented in the [application repository](https://github.com/LanceSandino/aws-sso-profile-sync).

## Validation

The candidate workflow checks style, audit and native installation using freshly
built local archives. Set repository variable `APP_SOURCE_REF` to the exact
reviewed application commit, or provide `app_ref` when dispatching the candidate
workflow. The default is `feature/release-review`. Native parser checks preserve
the exact release version and SemVer build metadata.

The published workflow validates all four actual public release archives before
installing the unchanged public formula on Linux amd64/arm64 and macOS Intel/ARM.
Set `PUBLISHED_SOURCE_SHA` to the stable version tag's exact application commit.
It verifies that GitHub's tag resolves to that commit, checks all archive hashes,
requires native smoke-test and real AWS acceptance metadata to be `PASS`, and
compares the formula with the application generator's output. It then runs strict
Homebrew audit, installs from the public release URLs, compares the installed
native binary with its verified archive, and runs the offline formula test.
Archive metadata does not include a source SHA; tag verification is separate.
The workflow runs for formula changes or a manual dispatch after publication.

Homebrew setup precedes the application checkout, has a five-minute limit and
uses the job's temporary repository token. Both checkouts disable credential
persistence. The official setup action removes its temporary Git authentication
header during post-job cleanup. The application checkout uses a separate
runner-owned global Git configuration. Installation tests use isolated HOME and
AWS file paths, with inherited AWS variables removed. CI does not publish, push,
tag, merge or update formulae automatically.

## Formula updates

Use the application repository's `scripts/homebrew.py` against the version's four
verified release archives and `SHA256SUMS`, then review the generated
`Formula/aws-sso-profile-sync.rb`. Keep release URLs and hashes exactly as
generated. Publish matching assets before merging the formula; never substitute
placeholder hashes. The owner controls release publication and tap visibility.
