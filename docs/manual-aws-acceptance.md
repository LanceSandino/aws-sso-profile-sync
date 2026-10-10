# Manual AWS acceptance

Stable **2.0.1 passed R01–R09** on an owner-authorized system. See the [release's acceptance record](https://github.com/LanceSandino/aws-sso-profile-sync/blob/v2.0.1/.github/release-acceptance.json). Observed scope was two named sessions, two profile regions and one Identity Center region, including independent AWS CLI discovery and generated-profile identity, preservation, explicit overrides, aliases and real token refresh. Refresh used an operator-forced expiry of a copied tool token; natural-expiry R07 and other tenants, partitions and provider regions were not certified.

This document is a repeatable maintainer procedure, not a pending-installation checklist. Run it for a new release or another environment only on an authorized machine with legitimate IAM Identity Center access. Development tests and CI must never access real AWS. No real account, organization, Identity Center instance, permission set or assignment needs to be created. Keep credentials and tenant evidence private; Floci results do not substitute for real acceptance.

## Preflight and recovery

Identify the intended tenant start URL, SSO region, named session, expected account-role visibility and profile region from known access. Record the candidate version and AWS CLI v2 version. Choose the explicit shared-config and private tool-state paths. Inventory file owner/modes and existing unmanaged profiles; stop on unexpected symlinks or permissions.

Create a secure, versioned backup of the chosen config together with adjacent `.aws-sso-sync.json` and `.aws-sso-sync.intent` if present. Preserve bytes, owner and permissions; record which files were absent. Keep backups outside shared logs. Record a restore procedure for the coherent file set. The lock file is coordination state and should not be copied over an active writer. Never paste token cache JSON, tokens, client secrets, credential bodies or device codes into evidence.

## Operator commands

Set `CONFIG`, `STATE`, `START_URL`, `SESSION`, `SSO_REGION`, `PROFILE_REGION` and `ROLE` on that authorized machine. These are placeholders for operator-chosen values, not shell defaults. Commands below intentionally include explicit paths and session. Begin with a private copy of the original configuration and a separate state directory; check the original file remains byte-identical before considering an installation into the daily workflow.

```bash
aws-sso-profile-sync doctor --config-file "$CONFIG" --state-dir "$STATE" --format json
aws-sso-profile-sync login --config-file "$CONFIG" --state-dir "$STATE" \
  --sso-start-url "$START_URL" --sso-session-name "$SESSION" --sso-region "$SSO_REGION" --open=false
aws-sso-profile-sync discover --config-file "$CONFIG" --state-dir "$STATE" \
  --sso-start-url "$START_URL" --sso-session-name "$SESSION" --sso-region "$SSO_REGION" --format json
aws-sso-profile-sync plan --config-file "$CONFIG" --state-dir "$STATE" \
  --sso-start-url "$START_URL" --sso-session-name "$SESSION" --sso-region "$SSO_REGION" \
  --region "$PROFILE_REGION" --role "$ROLE" --format json
```

Verify visible accounts/roles against expected access. Select multiple exact roles by repeating `--role`; do not infer privileged choices. Confirm plan contains only intended identities, preserves unmanaged config, and changes no file/cache bytes, modes or mtimes. Inspect conflicts before proceeding; no automatic adoption/deletion exists.

Only after reviewing the plan, run explicit sync with the same flags and then repeat it:

```bash
aws-sso-profile-sync sync --config-file "$CONFIG" --state-dir "$STATE" \
  --sso-start-url "$START_URL" --sso-session-name "$SESSION" --sso-region "$SSO_REGION" \
  --region "$PROFILE_REGION" --role "$ROLE" --format json
```

Repeat sync must report unchanged profiles with no byte/mtime churn. Verify unrelated profiles/comments/settings and owner/modes against backup. If a write fails with uncertain state, inspect config/intent and use the documented recovery procedure before further writes.

Choose generated `PROFILE` names from actual results, then independently test AWS CLI profile consumption:

```bash
AWS_CONFIG_FILE="$CONFIG" aws configure list-profiles
AWS_CONFIG_FILE="$CONFIG" aws sts get-caller-identity --profile "$PROFILE"
```

Check returned account and role against the selected assignment. The tool uses a separate token cache; AWS CLI consumption and any required CLI login/cache interoperability must be observed here, not assumed. Record any incompatibility without copying secrets.

After a safe real expiry interval or approved operator test, observe read-only discovery refusing expired auth, explicit re-login/refresh, and AWS CLI behavior. Test multiple named sessions/SSO regions/profile regions and collision cases within existing legitimate access. Do not alter IAM permissions to manufacture fixtures. Capture only redacted stdout/JSON, allowed profile/account identifiers, versions, commands, outcomes and recovery notes.

## Acceptance record

The table below is a blank worksheet for a **new acceptance run**, not the 2.0.1 result. All nine released 2.0.1 cases passed as recorded above. Never carry a previous release's PASS into a changed source tree.

| ID | Observation | Status |
| --- | --- | --- |
| R01 | Named real IAM Identity Center login | NOT_RUN |
| R02 | Expected real account-role visibility | NOT_RUN |
| R03 | Real plan correct and strictly read-only | NOT_RUN |
| R04 | Explicit sync valid; unrelated configuration preserved | NOT_RUN |
| R05 | Repeated sync no-op; roles/names handled correctly | NOT_RUN |
| R06 | AWS CLI consumes profiles and returns expected identity | NOT_RUN |
| R07 | Real expiry, refresh/re-login and CLI interoperability | NOT_RUN |
| R08 | Multiple sessions and SSO/profile regions | NOT_RUN |
| R09 | Sanitized evidence and recovery procedure recorded | NOT_RUN |

Update an R-series result to PASS only after observing it on the real authorized system. Failures become tracked compatibility findings and receive local regression anchors when reproducible. Unexecuted observations remain **NOT_RUN**.
