# Lance Sandino's Homebrew tap

This tap scaffold is prepared for reviewed formulae from Lance Sandino's
projects. The first AWS SSO Profile Sync formula is pending an owner-published
release and a reviewed formula PR. This scaffold alone does not provide an
installable public formula.

After the owner publishes matching release assets and merges the formula:

```sh
brew tap LanceSandino/tap
brew install LanceSandino/tap/aws-sso-profile-sync
brew test LanceSandino/tap/aws-sso-profile-sync
```

Those commands are future installation instructions until that publication.
AWS SSO Profile Sync is a CLI; no GUI, service or AWS CLI dependency is installed.
Its formula smoke test uses disposable HOME, explicit AWS file paths and only
offline `--version` and `doctor`. Real AWS acceptance remains a separate owner
procedure documented in the application repository.

The candidate workflow checks style/audit/install using freshly built local
archives rather than unpublished release URLs. Set repository variable
`APP_SOURCE_REF` to the reviewable AWS SSO Profile Sync commit or feature branch,
or provide `app_ref` when dispatching it. The default is `feature/release-review`.
Native parser checks preserve the exact release version and SemVer build metadata.
Homebrew setup runs before the application checkout, has a five-minute limit and
uses the job's temporary repository token for this private tap. Both checkouts
disable credential persistence; the official setup action removes its temporary
Git authentication header during post-job cleanup.
On Homebrew versions that support explicit trust, CI trusts only the generated
application formula. The application source revision must be
available to the runner; missing/private/inaccessible source fails the job. CI
does not publish, push, tag, merge or update formulae automatically.

For a formula update, use the application repository's `scripts/homebrew.py`
against that version's four verified release archives and `SHA256SUMS`, then
review the generated `Formula/aws-sso-profile-sync.rb`. Keep release URLs and
hashes exactly as generated. Never replace real release hashes with placeholders.
