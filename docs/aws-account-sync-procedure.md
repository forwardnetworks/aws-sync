# AWS Account Sync Procedure

This guide explains how to keep a Forward AWS cloud setup aligned with an independently verified AWS account inventory. Forward NQE supports additive synchronization; lifecycle removals require a complete reviewed manifest.

It is written for readers who may not work in AWS every day. It focuses on the practical setup, preflight checks, and safe use of `awssync`.

Upgrading from an earlier release? Complete [Upgrading `awssync`](upgrading.md) before using this runbook.

## Operator Index

| Situation | Go directly to |
| --- | --- |
| Routine human update; no removals | [Apply the sync](#apply-the-sync) and use `safe-sync` |
| Scheduled additive update | [Run a dry plan](#run-a-dry-plan), then [apply](#apply-the-sync) |
| Independently approved account removal | [Reviewed manifest removal](#reviewed-manifest-removal) |
| Failed, partial, or ambiguous apply | [Apply recovery](#apply-recovery) |
| Webhook deployment or failed event | [Webhook operation](#webhook-operation) and [webhook recovery](#webhook-recovery) |
| External ID migration or rollback | [Add a customer-defined External ID](#add-a-customer-defined-external-id-to-an-existing-setup) |
| New setup not yet in Forward | [Onboard from AWS Organizations directly](#onboard-from-aws-organizations-directly) |
| Command stopped during an incident | [Common failure modes](#common-failure-modes) |

## Summary

Forward collects AWS by using configured credentials to read AWS network metadata. In multi-account setups, Forward still assumes a role in each collected account.

For many AWS accounts in the same AWS Organization, there are two separate requirements:

1. Forward should be able to discover AWS accounts from AWS Organizations for additive onboarding, while operators must understand that the snapshot exposes observed inventory rather than a complete configured-account manifest.
2. Forward must be able to assume a collection role in every account that should be collected.

`awssync` automates the Forward-side account list update for existing setups. It also has a separate `discover-org` onboarding mode for new setups that Forward has not collected yet. Neither mode creates IAM roles in AWS or grants Forward access to new accounts by itself. New accounts become collectable only after the expected IAM role exists in those accounts and trusts Forward.

This workflow supports both Forward IAM role and IAM user/access-key multi-account setups. In both modes, the existing Forward setup must have `assumeRoleInfos` entries with role ARNs so `awssync` can derive the role name and generate role ARNs for newly discovered accounts.

For routine human operation, use `safe-sync`. It runs the required preflight, uses a processed snapshot no older than 24 hours, previews the changes, refuses removals, prompts once, and writes rollback data:

```bash
./awssync-linux-amd64 safe-sync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX
```

See the one-page [Routine AWS Safe Sync](routine-safe-sync.md) handoff. Use the standard and expert commands later in this procedure only for automation, onboarding, External IDs, GovCloud, or independently reviewed account removals.

Important separation:

- Use the default NQE sync path for additive updates to an existing Forward AWS setup. It can add or re-enable observed accounts but cannot remove an account because it is absent.
- Use `sync-accounts` with a complete reviewed manifest for existing-setup lifecycle removals.
- Use `discover-org` only for initial onboarding. It calls AWS Organizations directly, writes files, and can POST a new Forward setup, but it does not PATCH an existing setup.

## AWS Terms

- **AWS account**: A billing/security boundary in AWS. Each account has a 12-digit account ID.
- **AWS Organization**: A group of AWS accounts managed together.
- **Management account**: The top-level AWS account for the Organization. This is sometimes called the root account, but AWS usually calls it the management account.
- **Member account**: Any AWS account that belongs to the Organization.
- **IAM role**: An AWS identity with permissions. In multi-account AWS setups, Forward assumes this role in each collected account.
- **IAM user/access key**: A stored AWS credential that Forward can use to assume the per-account roles in a multi-account setup.
- **External ID**: An optional safety value used in the IAM trust policy when Forward assumes a role. An IAM user/access-key setup can use either no External ID or a customer-defined value, as long as Forward and the target role trust policy use the same value.
- **Forward AWS setup**: The cloud account setup configured in Forward for AWS collection.

## Required AWS Model

For additive NQE discovery, one AWS account must be available for Forward to use as the Organizations discovery point. This is usually the AWS Organizations management account. A delegated administrator account can also work if it has the required Organizations permissions. The reviewed-manifest workflow does not require Forward to query AWS Organizations, but its manifest must come from independently authoritative lifecycle sources.

That discovery account must allow Forward to call AWS Organizations read APIs, including account-listing APIs such as `organizations:ListAccounts`. Forward uses that visibility to learn which AWS accounts exist.

Keep Organizations discovery permissions separate from member-account collection permissions. Grant organization-wide read APIs only to the management or delegated discovery account used for inventory. Do not grant AWS Organizations permissions to every member-account role. Member accounts instead need the consistent Forward collection role, its collection policy, and a trust policy that allows the configured Forward principal to call `sts:AssumeRole`.

Each collectable member account must also have a Forward collection role. The role name must be consistent across accounts because `awssync` builds role ARNs by taking the existing Forward setup role name and applying it to each discovered account ID. This same-role-name requirement applies to both Forward IAM role and IAM user/access-key multi-account setups.

Example:

```text
Existing configured role ARN:
arn:aws:iam::111111111111:role/ForwardRole

Discovered account:
222222222222

Generated role ARN:
arn:aws:iam::222222222222:role/ForwardRole
```

If the role is missing in account `222222222222`, Forward can add the account to the setup, but collection for that account will fail until AWS IAM is fixed.

A Forward cloud setup or snapshot can complete successfully even when collection fails for individual member accounts. Treat setup-level success as confirmation that the overall collection ran, not that every account was collected. Inspect the per-account collection logs for `sts:AssumeRole`, trust-policy, external-ID, and permission errors.

## Preflight Checklist

Complete these checks before running an additive NQE apply. For a manifest removal, use the independent inventory and review checks in [Reviewed manifest removal](#reviewed-manifest-removal) instead of treating NQE as authoritative.

### 1. Confirm Forward Is Collecting the AWS Organization Discovery Account

In Forward, confirm the AWS setup includes the management account or the delegated discovery account.

This matters for discovering additions, but it does not make NQE authoritative. NQE combines accounts that collected successfully with accounts visible through Organizations metadata, and collection or authorization failures can leave either set partial.

Expected result: the latest processed Forward snapshot includes the AWS setup and shows the accounts Forward observed. Do not use missing rows as deletion evidence.

### 2. Confirm AWS Organizations Permissions

The discovery account role must have read access to AWS Organizations. At minimum, verify it can list accounts.

An AWS CLI check can look like this:

```bash
aws organizations list-accounts
```

Run that command using credentials equivalent to the Forward AWS setup credentials for the Organizations discovery account.

Expected result: AWS returns the Organization accounts. If AWS returns `AccessDeniedException` or says Organizations is not in use, fix AWS access before using `awssync`.

### 3. Confirm the Forward Collection Role Exists in Member Accounts

For each account that should be collected, confirm the same role name exists.

AWS CLI example:

```bash
aws iam get-role --role-name ForwardRole
```

Run this check in representative member accounts, especially newly created accounts.

Expected result: the role exists and its trust policy allows Forward to assume it, including the external ID if the Forward setup uses one.

### 4. Confirm Forward Can Assume the Role

Before syncing a large account set, test at least one known member account in Forward.

Expected result: Forward setup/connectivity testing succeeds for the account and region set. If role assumption fails, fix IAM trust or permissions before applying a larger sync.

### 5. Confirm the Platform Query Scope

`awssync` gets observed AWS account rows from Forward NQE for additive synchronization.

The tool defaults to an inline Forward NQE source query for AWS account discovery. That inline query returns `Cloud Setup ID` from `cloudAccount.cloudSetupId`, which is required when one network has multiple AWS setups. When exactly one `--setup-id` is selected, the inline query is parameterized with that setup ID so Forward can scope the query before returning rows. `--query-id` is optional and should only be used when support intentionally overrides that query.

If a saved query declares a String setup parameter, pass `--query-setup-param PARAM_NAME` with exactly one `--setup-id`. Do not pass this flag to a saved query that does not declare the parameter; Forward rejects extra NQE parameters.

Expected result: the query returns AWS account IDs, names, and setup identifiers when there is more than one Forward AWS setup in the network. The built-in saved report that only returns name, ID, type, email, and collected status is not enough to separate multiple AWS setups.

## Build the Tool

```bash
make build
./bin/awssync --version
```

The binary is written to:

```text
./bin/awssync
```

Set common Forward inputs through environment variables:

```bash
export FWD_HOST=https://fwd.app
export FWD_USER=you@example.com
export FWD_PASS='secret'
export FWD_NETWORK_ID=NETWORK_ID
```

Use the Forward base URL for `FWD_HOST`; it can be SaaS or an on-prem Forward instance.

`FWD_NETWORK_ID` is optional when the Forward user can see exactly one network. In an interactive terminal, the CLI can show a numbered picker when multiple networks are visible and accepts either the menu number or the network ID. Automation should set `FWD_NETWORK_ID` or pass `--network-id` explicitly.

## Onboard From AWS Organizations Directly

Use this section when Forward has not collected the AWS Organization yet. The goal is to create onboarding files from AWS Organizations, not to update an existing Forward setup.

`discover-org` uses the AWS SDK default credential chain or `--aws-profile` to call `DescribeOrganization`, `ListAccounts`, and `ListParents`. If any call is denied, stop and fix Organizations access; continuing would create an incomplete onboarding inventory.

Generate the Forward UI upload file and create-setup POST body:

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --collect-region us-west-2 \
  --external-id Org:12345
```

Outputs:

- `fwd_accounts_data_<timestamp>.json`: flat account array for Forward's manual AWS account import step.
- `aws_create_payload_<timestamp>.json`: body for `POST /api/networks/{networkId}/cloudAccounts`.

With Forward credentials, omitting `--external-id` also checks that the setup name is unused and fetches Forward's generated External ID. After reviewing both files, add `--post --yes` to create the setup. Static-key collection uses a separate collector credential; supply its secret through `AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY`. Without that secret, the create payload contains a placeholder, reports `create_payload_ready: false`, and must not be POSTed.

Do not use `discover-org` for a setup that already exists. Use the additive NQE sync path below so the existing Forward regions, proxy settings, and stored credentials are preserved; use `sync-accounts` when a reviewed manifest authorizes membership removal.

For native IaC onboarding, prefer the Forward Terraform provider. The [quick start](quick-start.md#discover-before-onboarding) and `examples/terraform` cover provider and AWS-side bootstrap details without expanding this incident runbook.

## Run a Dry Plan

Start without `--apply`. This writes the planned PATCH payload to disk but does not update Forward. NQE account IDs must contain exactly 12 digits; a malformed row fails by default. `--allow-malformed-rows` skips and reports malformed rows for an urgent additive run, marks the observed inventory incomplete, and cannot authorize removals.

```bash
./bin/awssync \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --manual-output aws_sync_manual_payload.json
```

If support needs to override the platform query, pass an explicit query ID:

```bash
./bin/awssync \
  --query-id OVERRIDE_QUERY_ID \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json
```

If the network has multiple Forward AWS setups and only some should be synchronized, scope the run with `--setup-id`:

```bash
./bin/awssync \
  --setup-id AWS_SETUP_ID \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json
```

Repeat `--setup-id` to target more than one setup.

For example, preflight both selected setups before planning them:

```bash
./bin/awssync preflight \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --format human
```

Create a dry plan for the same setup pair:

```bash
./bin/awssync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --manual-output aws_sync_manual_payload.json
```

If the network has multiple AWS setups:
- interactive terminal: a setup picker is shown and accepts setup numbers or case-insensitive setup IDs.
- non-interactive: pass `--setup-id` values explicitly, or the run exits with a setup selection error.

Human-readable output is the default. Use `--json` (or `--format json`) for machine-readable output:

```bash
./bin/awssync --max-snapshot-age 24h --json
```

Review the summary per setup:

- `selected_setup_ids`, `snapshot_id`, and the configured, observed, and planned account counts identify the scope.
- `added_accounts`, `reenabled_accounts`, and `removed_accounts` are the change being approved. Standard NQE planning must show no removals.
- `nqe_candidate_row_count`, `nqe_org_unit_row_count`, `candidate_check`, and `organization_discovery_signal` diagnose discovery of additions; they never authorize removal.
- `ignored_nqe_item_count` is nonzero only with `--allow-malformed-rows`; without that flag, a malformed row stops planning.
- `role_name`, `external_id_configured`, regions, and proxy values show which existing setup metadata is preserved.
- `payload_sha256` fingerprints the generated file. `plan_digest` binds approval to the network, snapshot, policy, baseline, target, and classified changes.
- On apply, `rollback_output`, `rollback_sha256`, and `result_journal_output` identify the recovery artifacts. `patched` is `false` in a dry plan.

Then review `aws_sync_payload.json`. Confirm:

- Setup IDs are correct.
- Every account ID contains exactly 12 digits.
- Account names look correct.
- Role ARNs use the intended role name.
- External ID matches the existing setup. Use the separate `external-id` command below when intentionally adding, replacing, or clearing it.
- Regions and proxy settings match the existing Forward setup.
- The PATCH payload does not include access keys or secrets; those stored credentials remain unchanged in Forward.
- `removed_accounts` is empty. Standard NQE planning is additive; use `sync-accounts` with a reviewed manifest when removal is intended.

If `--manual-output` is used, confirm its setup keys match `selected_setup_ids` and each array contains the same reviewed role ARNs and External IDs.

## Add a Customer-Defined External ID to an Existing Setup

This is a separate, one-time hardening change, not a prerequisite for AWS Organizations discovery. It is supported for an existing IAM user/access-key setup: Forward keeps using the stored IAM user credentials, but includes the configured External ID when it calls `sts:AssumeRole` for each target account.

Use `external-id`, not NQE synchronization, for an isolated migration. It reads the setup directly, preserves account membership and setup metadata, and does not require a snapshot. First run a dry plan:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --format human
```

Review the prior and target states and confirm every payload entry has the intended value. With no `--account-id`, `--value` and `--clear` affect every account; repeat `--account-id` for a test subset. Use `--external-id-file` for reviewed per-account set/clear assignments; duplicate, malformed, wrong-setup, and unknown rows fail before PATCH. The [quick start](quick-start.md#add-an-external-id-to-an-existing-iam-user-setup) contains the CSV format.

Apply the same reviewed inputs. The guarded gateway writes the pre-change account list and PATCHable setup fields to `<output>.rollback.json` and maintains `<output>.result.json`:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --apply --yes
```

Stage the change in this order: apply the Forward value, run a snapshot and test a representative account, then require that identical `sts:ExternalId` in each target-role trust policy. Normal NQE, webhook, and manifest sync preserve existing per-account values. A mixed-ID setup that gains an account fails closed until `--external-id-file` assigns the new account explicitly.

Rollback order is the reverse dependency order: first relax or restore the affected AWS trust policies and verify role assumption, then restore Forward. Use the automatic rollback with [Apply recovery](#apply-recovery), or dry-run and apply `external-id --clear` or `--value PREVIOUS_VALUE` with the original `--account-id` scope. The human summary does not print the prior value; retrieve it from the owner-only rollback payload.

## Run Preflight Checks

`preflight` performs read-only checks and prints a human-readable readiness report. Add `--json` for structured output.

```bash
./bin/awssync preflight \
  --max-snapshot-age 24h
```

Expected result: `ready` is `true`, `nqe_aws_accounts` passes, `patch_plan` passes, and `account_removals` passes because the NQE plan is additive.

If `management_account_discovery` fails, the snapshot did not show any genuinely new uncollected AWS account candidates. An already configured row with `Collected? false` does not satisfy this check; it may simply be disabled or failing collection. Treat this as an addition/discovery diagnostic, never as removal authorization.

`aws_organizations_evidence` reports if the observed rows include candidate visibility or OU ID visibility for each selected setup. In multi-setup runs, the check lists setup IDs that lack this signal. Treat both as supporting evidence only:

- NQE absence never produces removals.
- `--prune-missing` is recognized only to return an actionable refusal.
- Manifest removals use `sync-accounts` and retain removal authorization and blast-radius ceilings.

## Apply the Sync

For a routine interactive sync, use the additive-only command:

```bash
./awssync-linux-amd64 safe-sync \
  --setup-id AWS-PROD
```

The remaining commands in this section are the standard and expert workflow. For non-interactive automation, run with `--apply` after reviewing the dry plan.

```bash
./bin/awssync \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --apply \
  --yes
```

Expected result: the command prints `patched_setup_count` greater than zero and each patched setup shows `patched: true`.

NQE sync is always additive: configured accounts missing from NQE remain in the payload. This is required because disabled accounts, failed accounts, authorization failures, accounts in another Organization, and transient errors may all be absent from NQE.

`--prune-missing` no longer creates a plan. It fails with: `--prune-missing is no longer supported: the NQE result is observed inventory, not an account manifest, so an account's absence cannot prove it should be deleted; use sync-accounts with a reviewed manifest instead`.

### Reviewed Manifest Removal

For an approved removal, build a complete manifest from sources that own account lifecycle: direct AWS Organizations inventory, the account-vending system or CMDB, approved standalone-account inventory, and explicit closure or transfer records. Start from the accounts currently configured in Forward and keep any account whose lifecycle is uncertain. Do not build the manifest from NQE or collection success.

The file is a non-empty JSON array of unique, exactly 12-digit IDs and optional names. It must contain every account that should remain in exactly one setup:

```json
[
  {"id": "111111111111", "name": "security"},
  {"id": "222222222222", "name": "production"}
]
```

Create a dry plan and inspect every `added_accounts` and `removed_accounts` entry:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id AWS-PROD \
  --accounts-file reviewed-accounts.json \
  --output aws_manifest_plan.json
```

Then apply with both blast-radius ceilings. `--max-removals` limits the count and `--max-removal-percent` limits the percentage of that setup's current configured accounts:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id AWS-PROD \
  --accounts-file reviewed-accounts.json \
  --output aws_manifest_plan.json \
  --apply \
  --yes \
  --allow-removals \
  --max-removals 10 \
  --max-removal-percent 5 \
  --allow-unattended-destructive
```

Choose both nonzero limits from the reviewed plan, leaving enough room only for the approved account IDs. A removal is blocked if `--allow-removals` or either ceiling is omitted, or if either ceiling is exceeded. `--allow-unattended-destructive` is required because `--yes` skips the human confirmation and Forward provides no atomic compare-and-swap token. For an attended apply, keep the removal controls but omit `--yes` and `--allow-unattended-destructive`; type `apply` after reviewing the preview. All paths use the same guarded apply gateway.

To apply an exact reviewed **non-destructive** payload file later without recomputing it:

```bash
./bin/awssync apply-plan \
  --plan aws_sync_payload.json \
  --yes
```

Do not use `apply-plan` as a substitute for the authoritative-manifest removal workflow. Run lifecycle removals through `sync-accounts` with the reviewed manifest and current removal ceilings. `apply-plan` remains useful for reviewed additive payloads and rollback recovery; it re-reads current state and routes through the same gateway.

Before the first PATCH, both normal apply and `apply-plan` write a pre-change PATCH payload beside the plan as `<plan>.rollback.json`. It contains the complete `assumeRoleInfos` account list plus `type`, `name`, `regions`, `regionToProxyServerId`, and `proxyServerId`. It does not capture the GET-returned fields `collect`, `connectionTimeoutSeconds`, `requestTimeoutSeconds`, `numVirtualizedDevices`, or `useForwardAccountToAssumeRole`.

This omission is safe for restoring an `awssync` change because Forward PATCH is a top-level merge: fields absent from the request body are left unchanged. The rollback restores the fields that `awssync` PATCHes without replacing those five settings. It is not a full backup of the setup and must not be used to reconstruct one from scratch. The apply summary includes its path and SHA-256. Use the result journal and recovery procedure below before applying the rollback.

### Apply Recovery

Every apply first creates `<output>.result.json` and updates it atomically after each setup disposition. Inspect it before retrying a command that failed or lost its terminal output:

```bash
jq '{plan_digest, network_id, setups}' aws_sync_payload.result.json
```

The per-setup status is `planned`, `pending`, `applied`, `conflicted`, or `failed`. `applied` means the PATCH completed and was journaled. `conflicted` means the immediate pre-PATCH re-read detected a changed setup and no PATCH was sent for that setup. `pending` after a crash is ambiguous: read the actual Forward setup before deciding whether to retry or roll back. In a multi-setup run, treat each setup independently and do not assume all-or-nothing behavior.

The pre-change PATCH payload is `<output>.rollback.json`; its path and SHA-256 are also printed in the apply summary. After checking the journal and current Forward state, restore it with:

```bash
./bin/awssync apply-plan \
  --plan aws_sync_payload.rollback.json \
  --yes
```

If that rollback removes or disables accounts that were added by the original apply, it is itself an unattended destructive apply. Review the exact difference and add all four controls:

```bash
./bin/awssync apply-plan \
  --plan aws_sync_payload.rollback.json \
  --yes \
  --allow-removals \
  --max-removals APPROVED_COUNT \
  --max-removal-percent APPROVED_PERCENT \
  --allow-unattended-destructive
```

Account ordering matters only to byte-level comparisons. `sync-accounts` rebuilds the reviewed account set in sorted order, so using it to restore the same accounts can produce a different raw endpoint hash even though the configuration is semantically identical. In live validation, applying the emitted rollback preserved the original account order and reproduced the pre-change endpoint hash byte-for-byte. Use the rollback path when byte-identical restoration matters.

Do not blindly rerun an ambiguous apply: a PATCH may have succeeded before its result could be persisted. Keep the payload, rollback, and result files together until a new Forward snapshot confirms recovery.

To recompute and apply for two selected setups after reviewing the expected changes:

```bash
./bin/awssync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --apply \
  --yes
```

NQE multi-setup runs remain additive. Run `sync-accounts` separately for each setup whose reviewed manifest authorizes removals.

## Validate After Apply

After applying:

1. Run or wait for a new Forward snapshot.
2. Confirm snapshot processing completes.
3. Confirm expected AWS accounts appear in Forward.
4. Check collection errors for newly added accounts.

Useful commands:

```bash
./bin/awssync status
```

```bash
./bin/awssync wait \
  --snapshot-id SNAPSHOT_ID
```

`status --json` reports `observation_atomic: false`. It reads Forward's latest-processed endpoint and snapshot list separately, so even matching responses are an operational view rather than one atomic point-in-time observation. A mismatch is reported in `latest_list_consistent` and `observation_warning`.

Planning rejects a processed snapshot timestamp more than five minutes ahead of the local clock. A smaller future offset is treated as ordinary clock skew and age zero. For a larger offset, correct NTP or the bad timestamp rather than bypassing freshness checks.

If a new account appears in the Forward setup but fails collection, the most likely cause is missing or incorrect IAM role setup in that AWS account.

## Ongoing Automation

Generated payload, rollback, result-journal, manual, and applied-audit files are written atomically with owner-only `0600` permissions. Treat them as secrets when a workflow uses static AWS access keys, and configure retention accordingly.

The client retries transient `429`, `502`, `503`, and `504` failures only for idempotent reads, NQE reads, and full-state PATCH operations. It does not retry cloud-account or webhook creation POSTs. After an ambiguous create failure, inspect Forward for the requested object before retrying manually.

The automation policy is additive NQE sync. For a new account, create the Forward collection role, run a Forward snapshot that observes the account, run `awssync` against that processed snapshot, and validate the next collection.

Lifecycle removal is a separate workflow. Confirm the closure, transfer, or retirement in an authoritative lifecycle system, update and review the complete manifest, then run `sync-accounts` with narrow removal ceilings. Do not remove the collection IAM role first and then interpret the resulting NQE absence as authorization.

### Webhook Operation

For event-driven additive workflows, `awssync serve-webhook` can receive Forward `SNAPSHOT_READY` events and run the sync against the exact snapshot from the event. It cannot remove accounts from NQE absence.

Start the receiver:

```bash
./bin/awssync serve-webhook \
  --network-id NETWORK_ID \
  --listen :8080 \
  --path /forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --webhook-state-file /var/lib/awssync/webhook-state.json \
  --apply \
  --yes
```

Create the Forward webhook through the Forward API:

```bash
./bin/awssync configure-webhook \
  --network-id NETWORK_ID \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --test-webhook
```

An applying receiver will not start without `--yes`, an explicit `--network-id`, and both Basic Auth values. The `--webhook-basic-username` and `--webhook-basic-password` values on `configure-webhook` must match the receiver values on `serve-webhook`; Forward includes them on delivery.

### Webhook Recovery

The receiver persists each accepted event before returning `202`. By default, queue state is `$UserConfigDir/awssync/webhook-state.json`; on Linux that is normally `$HOME/.config/awssync/webhook-state.json`. Services should use `--webhook-state-file` with an explicit service-owned path. Keep it on durable local storage, retain it across restarts, and do not share one state file between daemon processes because there is no interprocess lock. The file is atomically written with mode `0600`; keep its parent directory service-owned. `/healthz` reports `pendingDepth` and `deadLetterDepth` in addition to the in-memory `queueDepth`.

Failed jobs run at most five times. The delays after failures are 1, 2, 4, and 8 seconds (the exponential delay is capped at 30 seconds). After the fifth failure, the full event, attempt timestamps, and last error remain under `dead_letter_events` in the state JSON. Inspect pending and dead-letter work with the service user, for example:

```bash
jq '{pending_events, dead_letter_events}' /var/lib/awssync/webhook-state.json
```

Correct the underlying error before draining a dead-letter entry. Then POST the original event body to the configured receiver path with the normal Basic Auth credentials. Re-delivery removes that entry from `dead_letter_events`, persists it as a fresh pending job with a reset failure count, and returns `202`; the new cycle is bounded to five attempts again. Normal scope and snapshot-watermark checks still run, so an obsolete event may be rejected instead of requeued. To discard an obsolete entry, stop the receiver, remove only that exact record from `dead_letter_events`, preserve mode `0600`, and restart. Do not edit the state file while the receiver is running.

`configure-webhook` is repeatable. It creates a missing webhook and updates the same named webhook if it already exists. If only specific AWS setups should sync from webhook events, add one or more `--setup-id` values. The tool adds those setup IDs to the receiver URL so the receiver can scope the run. Add `--webhook-per-setup` to create or update one webhook per setup ID.

```bash
./bin/awssync configure-webhook \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --setup-id AWS \
  --setup-id AWS-SANDBOX \
  --webhook-per-setup
```

Important SaaS caveat: if Forward is SaaS, `--webhook-url` must be reachable from Forward SaaS over the internet. A localhost, RFC1918, VPN-only, or private URL will not work unless the receiver is exposed through an approved public endpoint, reverse proxy, or tunnel. If Forward is on-prem, the URL only needs to be reachable from the Forward app server.

### Install the Receiver as a Service

For production webhook use, run `awssync serve-webhook` as a supervised service on a host that can reach Forward and that Forward can reach on the webhook URL.

Recommended service practices:

- Run as a dedicated low-privilege user such as `awssync`.
- Store `FWD_HOST`, `FWD_USER`, `FWD_PASS`, `AWSSYNC_WEBHOOK_BASIC_USERNAME`, and `AWSSYNC_WEBHOOK_BASIC_PASSWORD` in a protected service environment file.
- Pin one `FWD_NETWORK_ID` or `--network-id` and reject events from every other network.
- Put `--webhook-state-file` on persistent service-owned storage and preserve its `0600` mode.
- Start in dry-run mode first, without `--apply`, and confirm webhook delivery and payload generation.
- Add `--apply --yes` only after dry-run output is reviewed.
- Use `--allow-no-candidates` only after confirming management or delegated discovery is working.
- Use `--allow-no-org-evidence` only after independent verification that AWS Organizations discovery remains complete.
- Send service logs to the normal log collection system.
- Alert when `/healthz` reports a nonzero `deadLetterDepth`, and retain the webhook state file across service restarts.

Linux systemd command example:

```ini
ExecStart=/usr/local/bin/awssync serve-webhook --network-id NETWORK_ID --listen 0.0.0.0:8080 --webhook-state-file /var/lib/awssync/webhook-state.json --apply --yes
EnvironmentFile=/etc/awssync/awssync.env
Restart=on-failure
RestartSec=10
```

For temporary SaaS testing, a short-lived tunnel such as `trycloudflare` can expose a local receiver. Account-less tunnels are suitable for testing only and should not be used for production automation.

## Common Failure Modes

### No AWS Accounts Found

Likely causes:

- Forward has not collected the AWS Organizations discovery account.
- The latest processed snapshot is too old.
- The NQE query does not return AWS account rows.
- AWS Organizations permissions are missing.

Fix: verify the discovery account setup, run a new snapshot, and rerun the dry plan.

### Snapshot Has an Invalid Future Timestamp

Likely causes:

- the `awssync` host clock is behind Forward;
- Forward returned a bad `processedAt` or `createdAt` value.

Fix: compare UTC time on both systems and correct NTP or the source timestamp. Planning tolerates up to five minutes of ordinary clock skew and rejects anything further ahead; changing `--max-snapshot-age` does not make a future timestamp valid.

### discover-org AWS Organizations Access Denied

Likely causes:

- The selected AWS profile or environment credentials are from a member account without Organizations read access.
- The credentials are not from the management account or an Organizations delegated administrator.
- IAM policy is missing `organizations:DescribeOrganization`, `organizations:ListAccounts`, or `organizations:ListParents`.
- AWS Organizations is not enabled for that account set.

Fix: switch to credentials that can read AWS Organizations, or grant those read-only Organizations permissions. `discover-org` stops on these errors because a partial account list would create an unsafe onboarding payload.

### discover-org Setup Already Exists

Likely causes:

- The `--setup-id` name is already used by a Forward cloud account setup.
- You are trying to use onboarding mode for an existing setup.

Fix: use the NQE sync path for existing setups. `discover-org` intentionally does not PATCH existing setups.

### No Candidate Accounts Visible

Likely causes:

- The AWS Organization has no accounts that are currently uncollected.
- Forward is not collecting the management or delegated discovery account.
- The discovery account role lacks AWS Organizations read permissions.
- The query override does not include the `Collected?` column.

Fix: run `preflight`, verify `management_account_discovery`, and confirm the AWS Organizations access check. This affects discovery of additions. Make all removal decisions from a complete independently reviewed manifest, never from this NQE state.

### Webhook Does Not Trigger Sync

Likely causes:

- The Forward webhook URL is not reachable from the Forward app server.
- Forward SaaS is pointed at a private or VPN-only receiver URL.
- Basic Auth values in Forward do not match the receiver.
- The applying receiver has no explicit `--network-id`, so it refuses to start.
- The event is outside the receiver's configured network scope.
- The event failed five times and is in `dead_letter_events`.

Fix: run `configure-webhook --test-webhook`, check receiver logs and the durable state file, and confirm `/healthz` is reachable from the same network path Forward will use. Follow [Webhook recovery](#webhook-recovery) for a dead-lettered event.

### Missing Setup Metadata

Likely causes:

- The query returned a setup ID that does not match a Forward AWS setup.
- Multiple AWS setups exist, but the platform query response does not include the setup identifier.

Fix: verify the platform query output. If support is intentionally bypassing the platform query, use an override query that includes the Forward setup ID.

### Unable to Determine Role ARN Name

Likely causes:

- The existing Forward setup has no `assumeRoleInfos`.
- The existing account entry does not include a valid role ARN.
- The setup is single-account or collect-all CAP rather than a multi-account role-ARN setup.

Fix: configure and test at least one known-good AWS account in the Forward setup first. `awssync` needs that setup as the template for role name, regions, proxy, and optional external ID.

### Account Added but Collection Fails

Likely causes:

- The Forward IAM role was not created in the new AWS account.
- The trust policy does not allow Forward to assume the role.
- The external ID in AWS does not match the Forward setup.
- The role policy lacks required read permissions.

Fix: repair IAM in the AWS account, then rerun collection. The account list may already be correct in Forward.

### Organizations Visibility and AssumeRole Decision Table

Use both AWS Organizations inventory and the per-account `sts:AssumeRole` result before deciding whether to repair IAM or remove an account.

| Visible in AWS Organizations | `sts:AssumeRole` | Interpretation | Recommended action |
| --- | --- | --- | --- |
| Yes | Succeeds | Account discovery and collection access are healthy. | Keep the account configured. |
| Yes | Fails | The account is active and discoverable, but its collection role, trust policy, external ID, or permissions are incorrect. | Repair IAM in the member account; do not remove it from Forward. |
| No | Succeeds | Forward can still reach the configured role, but the discovery account does not report the account. Organization membership or discovery scope may have changed. | Verify the management or delegated discovery account and the account's Organization membership; do not remove it based only on discovery. |
| No | Fails | The account may be closed, removed, or moved, or its IAM configuration may also be broken. | Confirm the account lifecycle independently in AWS. Remove it only after that confirmation; otherwise repair discovery or IAM. |
