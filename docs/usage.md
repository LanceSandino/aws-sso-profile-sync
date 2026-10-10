# Using AWS SSO Profile Sync

The normal workflow is: authenticate once, discover your account-role assignments, review a plan, and sync the selected profiles. Later syncs update those managed profiles while preserving unrelated configuration.

The original tool has been used daily across more than 50 AWS accounts. Version 2.0.1 is a substantial rewrite, with automated tests using synthetic AWS SSO data. Real IAM Identity Center login, refresh and AWS CLI profile consumption are tracked separately in the [release acceptance record](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json). The network examples below describe the authorized operator workflow; development tests never use real AWS.

## Install and check the executable

Follow [installation and rollback](install.md) for source builds, release archives, checksum verification and an explicit installation prefix. From a reviewed source checkout with Go 1.25 or newer:

```bash
GOBIN="$(pwd)/dist/local-bin" go install .
./dist/local-bin/aws-sso-profile-sync --version
./dist/local-bin/aws-sso-profile-sync --help
```

The examples below use `aws-sso-profile-sync` on PATH. Use the installed executable's full path if you have not added its directory to PATH. A source build installs the checkout you built; select the `v2.0.1` tag as shown in the installation guide. The public Homebrew tap installs released archives.

## Choose the session and files

Use the IAM Identity Center start URL and SSO region provided for your organization. The start URL is required for network commands and must be HTTPS, without embedded credentials, a query or a fragment. The SSO region locates Identity Center; the profile region is the default region for later AWS service commands. Requested region/output defaults apply to new profiles and missing settings; existing values are preserved unless you explicitly authorize replacement.

Replace these example values before any authorized real use. `example.invalid` is a placeholder, not an AWS tenant. `ReadOnly` is an example role name; select an exact role actually shown by discovery.

```bash
CONFIG="/absolute/path/to/aws/config"
STATE="/absolute/path/to/profile-sync-state"
START_URL="https://example.invalid/start"
SESSION="work"
SSO_REGION="us-east-1"
PROFILE_REGION="us-east-2"
ROLE="ReadOnly"

# A Bash array keeps the same session and paths on each command.
COMMON=(
  --config-file "$CONFIG"
  --state-dir "$STATE"
  --sso-start-url "$START_URL"
  --sso-session-name "$SESSION"
  --sso-region "$SSO_REGION"
)
```

The explicit config path makes it clear which file will be managed. Without `--config-file`, the tool uses `AWS_CONFIG_FILE` when set, otherwise `~/.aws/config`. Without `--state-dir`, authentication state lives in `~/.aws-sso-profile-sync`.

Before the first real sync, back up the chosen config and any adjacent `.aws-sso-sync.json` and `.aws-sso-sync.intent` files as a coherent set. The [manual acceptance procedure](manual-aws-acceptance.md) covers backup and recovery checks. Installation itself does not modify AWS configuration.

## Optional settings and contexts

Use a settings file when you regularly repeat the same tenant, session, roles or paths. Settings are optional: without `--settings-file` or `--context`, the CLI never reads one and existing flag behavior is unchanged. Create and maintain the file yourself; the tool only reads it.

For example, `~/.aws-sso-profile-sync/settings.json` can contain:

```json
{
  "schema_version": 1,
  "default_context": "work",
  "contexts": {
    "work": {
      "sso_start_url": "https://example.invalid/start",
      "sso_session_name": "work",
      "sso_region": "us-east-1",
      "region": "us-east-2",
      "roles": ["ReadOnly"],
      "prefix": "team_",
      "auto_prefix": true,
      "output": "json",
      "config_file": "../.aws/config",
      "state_dir": "work-state"
    },
    "sandbox": {
      "sso_start_url": "https://sandbox.invalid/start",
      "sso_session_name": "sandbox",
      "sso_region": "us-west-2",
      "region": "us-west-2",
      "roles": ["ReadOnly"],
      "config_file": "sandbox/config",
      "state_dir": "sandbox/state"
    }
  }
}
```

These URLs and role names remain placeholders for later authorized use. The file must belong to your user, be a regular file smaller than 1 MiB, and have no group/world write permission; `chmod 600` is a suitable setting. Symlink files and path components are rejected, apart from standard macOS system aliases. Unknown or duplicate JSON keys, malformed values and unsupported schema versions are errors. The settings file cannot enable `--override-profile-settings`. Error messages do not echo settings contents.

Select the context on each command:

```bash
aws-sso-profile-sync login --context work --open=false
aws-sso-profile-sync discover --context work
aws-sso-profile-sync plan --context work
# After reviewing the plan:
aws-sso-profile-sync sync --context work
aws-sso-profile-sync doctor --context work
```

`--context` alone reads `~/.aws-sso-profile-sync/settings.json`. That location is fixed relative to HOME: changing `--state-dir` does not change which settings file is loaded. To select another file, use `--settings-file FILE`:

```bash
aws-sso-profile-sync plan --settings-file ./settings.json --context sandbox
aws-sso-profile-sync plan --settings-file ./settings.json --role PowerUser --auto-prefix=false
```

In the second example, the declared `default_context` selects `work`; an explicit `--role` replaces the configured role list, and explicit boolean values override configured values. With no selected or declared default context, a sole context is used. Multiple contexts require an explicit choice. A missing file or context is an error, never a fallback to another tenant.

For requested defaults, precedence is built-in defaults, then context values, then explicitly supplied flags. Existing managed region/output values are still preserved unless `--override-profile-settings` is explicit. Configured `region` therefore takes precedence over region environment fallbacks, while an explicit `--region` wins over both. Context values are optional; omitted values retain the CLI's existing defaults. An explicitly configured `sso_session_name` stays bound to that name, including `default`.

Relative `config_file` and `state_dir` values resolve against the settings file's directory; they are not shell-expanded. In this example, the work config resolves to `~/.aws/config`, while work token state lives under `~/.aws-sso-profile-sync/work-state`. Relative paths passed explicitly through CLI flags keep their existing meaning relative to the current working directory.

Allowed context fields are `sso_start_url`, `sso_session_name`, `sso_region`, `region`, `roles` (an array of exact role names), `prefix`, `auto_prefix`, `output`, `config_file` and `state_dir`. Do not store tokens, passwords, AWS credentials, test endpoints or command-action options in settings; they are rejected. A context supplies defaults only: it does not log in, open a browser, refresh a token or make read-only commands write files.

## Inspect the existing config offline

```bash
aws-sso-profile-sync doctor --config-file "$CONFIG" --state-dir "$STATE"
aws-sso-profile-sync list --config-file "$CONFIG" --state-dir "$STATE"
```

Both commands work without login or network access. `doctor` checks strict parsing and ownership/recovery state. `list` shows configured profiles, distinguishing tool-owned profiles from unmanaged profiles. Neither command creates configuration, tokens or metadata.

If parsing or ownership fails, resolve that error before continuing. The tool preserves a malformed file rather than replacing it with whatever sections it could read.

## Log in explicitly

```bash
aws-sso-profile-sync login "${COMMON[@]}" --open=false
```

Open the verification URL printed on stderr and complete authorization. `--open=false` leaves that step to you. Omit it to let the tool attempt to open your browser; if opening fails, the printed URL is still available. If authorization needs more time, use `--timeout 5m`; the default invocation deadline is two minutes and the maximum is ten minutes.

Login validates a cached token, refreshes it when possible, or starts a device flow. Successful authentication is saved privately under `"$STATE/auth"`, bound to the exact named session, tenant URL and SSO region. Keep token files private; they contain bearer tokens and client registration secrets.

`discover`, `plan` and `sync` never start login or refresh authentication. When a token is missing or expired, run `login` again. Explicit re-login can recover revoked tokens and invalid refresh grants. An insecure or malformed cache produces an error for inspection rather than being silently overwritten.

## Discover available roles

```bash
aws-sso-profile-sync discover "${COMMON[@]}"
```

Discovery lists the account IDs, roles and account labels visible to the logged-in session. It does not modify your configuration. A failure anywhere in paginated discovery returns an error rather than a partial list that could be mistaken for the full set of assignments.

Choose the role names from these results. If there is one distinct role, planning can select it automatically and explain the choice. If there are several, pass one or more `--role` flags. Selecting two roles creates separate profiles for their account-role assignments:

```bash
aws-sso-profile-sync plan "${COMMON[@]}" \
  --region "$PROFILE_REGION" --role ReadOnly --role PowerUser
```

## Plan and review the changes

```bash
aws-sso-profile-sync plan "${COMMON[@]}" \
  --region "$PROFILE_REGION" --role "$ROLE"
```

The table shows the proposed profile results and before/after key values. Review the selected accounts and roles, session binding, profile region, output setting and generated names. The account ID and identity suffix distinguish similarly named accounts and different roles. Existing managed identities keep their names even if naming flags change.

| Result | Meaning |
| --- | --- |
| `created` | A new managed profile is proposed |
| `updated` | A missing setting would be filled, or an explicit override would change managed settings |
| `unchanged` | Managed identity and settings already match |
| `conflict` | Ownership, identity or external edits prevent a safe update |
| `stale` | A formerly managed assignment is no longer visible; its profile is retained |

Existing managed profiles keep their current `region` and `output`, even if you changed those values manually. A `setting_preserved` warning lists the profile, field, existing value and requested default when they differ. To deliberately replace those settings, review an explicit override plan, then use the same flag for sync:

```bash
aws-sso-profile-sync plan "${COMMON[@]}" --role "$ROLE" \
  --region eu-west-1 --output json --override-profile-settings
# After reviewing the requested replacement:
aws-sso-profile-sync sync "${COMMON[@]}" --role "$ROLE" \
  --region eu-west-1 --output json --override-profile-settings
```

The override covers only region/output on matching managed identities. It does not authorize unmanaged profile adoption, identity changes or session rebinding, and settings files cannot enable it.

`duplicate_profiles` warnings group aliases for the same normalized tenant URL, SSO region, account ID and role. Offline `doctor`/`list` inspect current profiles; a plan inspects its projected configuration. Warnings identify the aliases and a stable identity digest, retain every alias, and do not block a valid operation by themselves. Neither duplicate warnings nor sync automatically deduplicate or delete profiles.

Conflicts produce a nonzero exit and block sync. An existing manually configured profile is preserved; there is no automatic adoption or deletion. Stale profiles are informational and retained, including when a complete discovery returns no assignments.

For a review artifact suitable for scripts:

```bash
aws-sso-profile-sync plan "${COMMON[@]}" \
  --region "$PROFILE_REGION" --role "$ROLE" --format json > plan.json
```

JSON includes `schema_version: 1`, results, assignments, counts, proposed section values, a structured `diff`, before/after config hashes and optional structured `warnings`. Stdout contains JSON; progress and errors use stderr. The artifact may contain account identifiers and configuration values, so review it before sharing. It is not an apply file: sync always discovers and plans again.

## Sync with the same choices

After reviewing the plan, use the same paths, session, roles and settings:

```bash
aws-sso-profile-sync sync "${COMMON[@]}" \
  --region "$PROFILE_REGION" --role "$ROLE"
```

Sync locks the target, checks for changes since its snapshot, and applies authorized profile updates with an atomic replacement and recoverable ownership transaction. It preserves unrelated settings and comments. Repeating the same command should report `unchanged` and leave unchanged config bytes and modification time intact.

Inspect the resulting profiles offline:

```bash
aws-sso-profile-sync list --config-file "$CONFIG" --state-dir "$STATE"
```

`sync --dry-run` is equivalent to `plan` and writes no config or token state. A flags-only legacy invocation still selects `sync`; it now requires a separate explicit login.

Generated profiles use standard AWS shared-config keys, but the tool's token cache is separate from the AWS CLI cache. Do not assume profile generation also authenticates the AWS CLI. Test actual AWS CLI consumption as part of [manual acceptance](manual-aws-acceptance.md).

## Diagnose a problem

Start with offline diagnostics:

```bash
aws-sso-profile-sync doctor --config-file "$CONFIG" --state-dir "$STATE" --format json
```

To explicitly check live discovery with an existing valid token, use the session flags and `--probe`:

```bash
aws-sso-profile-sync doctor "${COMMON[@]}" --probe --format json
```

The probe does not start login or refresh a token. Common errors have direct next steps:

| Error | Next step |
| --- | --- |
| `login_required` | Run explicit login for the same session, URL and SSO region |
| `role_selection_required` | Discover the assigned roles and select exact names with `--role` |
| `auth_invalid` | Re-login for a rejected token; inspect malformed/insecure cache errors before changing files |
| `config_invalid` | Check the explicit path, config syntax, metadata and supplied values |
| `conflict` | Review the existing profile/session or external edit; do not delete ownership metadata to force an overwrite |
| `discovery_incomplete` | Resolve the network/service failure and rerun; no partial list was applied |
| `timed_out` / `canceled` | Check connectivity or authorization progress; increase the invocation timeout within its limit when appropriate |

An error during a write can occur after the config was replaced. If it reports uncertain commit state or retained intent, inspect the config together with its metadata before retrying. Offline `doctor` does not repair files. A later explicit sync reconciles a recognized pending transaction; unknown state stops for inspection. See [configuration recovery](install.md#configuration-recovery).

## Flag reference

Place flags after the command. `--help` lists the current defaults; Go's single-dash spellings also work.

| Flag | Use |
| --- | --- |
| `--settings-file` | Optional nonsecret JSON settings file; loaded only when requested |
| `--context` | Named settings context; alone uses `~/.aws-sso-profile-sync/settings.json` |
| `--sso-start-url` | Required HTTPS tenant URL for network commands, from a flag or selected context |
| `--sso-session-name` | Named session, default `default`; if omitted, one matching existing session can supply its name. An explicit `default` remains explicit |
| `--sso-region` | Identity Center service region, default `us-east-1` |
| `--region` | Profile region; precedence is explicit flag, context, `AWS_REGION`, `AWS_DEFAULT_REGION`, existing `[default]`, then `us-east-2` |
| `--role` | Exact assigned role; repeat for several roles |
| `--prefix` | Custom prefix for new names; takes precedence over automatic prefixes |
| `--auto-prefix=false` | Disable role-derived prefixes; automatic prefixes default to enabled |
| `--output` | Requested AWS profile output default, `json`; independent of CLI formatting |
| `--override-profile-settings` | Explicitly replace existing region/output on matching managed profiles; default false and forbidden in settings |
| `--format` | CLI `table` or schema-versioned `json`, default `table` |
| `--config-file` | Explicit shared-config path |
| `--state-dir` | Private authentication state root |
| `--open=false` | Show the login verification URL without opening a browser |
| `--timeout` | Positive invocation deadline up to `10m`, default `2m` |
| `--dry-run` | Read-only plan; valid only with `sync` or `plan` |
| `--probe` | Enable discovery for `doctor` |
| `--version` | Print the executable version |
| `--test-root`, `--test-endpoint` | Isolated loopback emulator mode for [development](development.md), not tenant configuration |

For the module boundaries and reasons behind these behaviors, see [architecture and design](architecture.md).
