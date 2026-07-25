# Upgrading `awssync`

This guide is for operators upgrading from the release that allowed NQE-based `--prune-missing`, allowed an applying webhook receiver without inbound credentials or a fixed network, and allowed unattended destructive applies without an additional acknowledgement.

Read this before replacing the binary. Three existing automation patterns now fail closed.

## Before the Upgrade

1. Disable scheduled jobs that pass `--prune-missing`.
2. Record the configured account IDs in every Forward AWS setup from Forward, a recent payload, or a rollback artifact. A rollback is sufficient here for the account list, but it is not a full setup backup. This is the baseline for review; do not reconstruct it from NQE.
3. Back up the current webhook service definition and, if it exists, its webhook state file.
4. Identify every automation path that can remove or disable accounts, including `sync-accounts --yes` and destructive `apply-plan` runs.

A rollback artifact contains the complete `assumeRoleInfos` account list and the PATCHable setup fields. It does not capture `collect`, `connectionTimeoutSeconds`, `requestTimeoutSeconds`, `numVirtualizedDevices`, or `useForwardAccountToAssumeRole`. Applying it is safe for restoration because Forward PATCH leaves absent top-level fields unchanged, but keep a separate full setup record if those settings must be backed up or the setup may need to be reconstructed.

## 1. Replace `--prune-missing` With a Reviewed Manifest

`--prune-missing` now exits with an error and never creates or applies a plan. Removing the flag makes the normal NQE workflow additive; it does **not** preserve the old removal behavior.

Forward NQE returns accounts observed in a snapshot. It can combine successfully collected accounts with accounts visible through Organizations metadata, but collection failures, authorization failures, discovery scope, and transient errors can omit live accounts. It is not an account manifest. This is why NQE absence once caused live accounts to be deleted and is no longer accepted as removal evidence.

`sync-accounts` with a complete, independently reviewed manifest is the only supported removal path.

### Build the manifest from authoritative sources

Start with the account IDs currently configured in the Forward setup. Then reconcile that baseline against sources that own account lifecycle, such as:

- a direct AWS Organizations `ListAccounts` call made with management-account or authorized delegated credentials;
- the account-vending system or CMDB;
- the approved inventory for standalone accounts or accounts in another Organization;
- closure, transfer, or retirement records that identify the exact IDs approved for removal.

Do not use NQE output, a failed collection, a missing IAM role, or `Collected? false` to decide that an account should be absent from the manifest.

For one AWS Organization, a direct AWS CLI export can provide one input to the review:

```bash
AWS_PROFILE=org-readonly aws organizations list-accounts \
  --query 'Accounts[?State==`ACTIVE`].{id:Id,name:Name}' \
  --output json > org-accounts.json
```

Run this against every relevant Organization. Add separately approved standalone accounts, and keep accounts whose lifecycle cannot be confirmed. If several reviewed JSON arrays must be combined, concatenate and sort them without hiding duplicates:

```bash
jq -s 'add | sort_by(.id)' \
  org-accounts.json \
  approved-standalone-accounts.json \
  > reviewed-accounts.json
```

The manifest must be a non-empty JSON array and must contain every account that should remain in the one selected setup:

```json
[
  {
    "id": "111111111111",
    "name": "security"
  },
  {
    "id": "222222222222",
    "name": "production"
  }
]
```

Every `id` must be a unique string containing exactly 12 digits. `sync-accounts` rejects unknown fields, duplicates, malformed IDs, and an empty manifest.

### Dry-run, review, and apply

Create a plan for exactly one setup:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id AWS-PROD \
  --accounts-file reviewed-accounts.json \
  --output aws_manifest_plan.json
```

Have an operator compare every `added_accounts` and `removed_accounts` ID with the current Forward setup and the lifecycle records. Stop if the removed set contains anything not independently approved.

For a human-attended apply, omit `--yes` and type `apply` only after reviewing the preview:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id AWS-PROD \
  --accounts-file reviewed-accounts.json \
  --output aws_manifest_plan.json \
  --apply \
  --allow-removals \
  --max-removals APPROVED_COUNT \
  --max-removal-percent APPROVED_PERCENT
```

Set both nonzero ceilings just above the reviewed change, not to the full account population. An unattended equivalent also requires both `--yes` and the acknowledgement described below:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id AWS-PROD \
  --accounts-file reviewed-accounts.json \
  --output aws_manifest_plan.json \
  --apply \
  --yes \
  --allow-removals \
  --max-removals APPROVED_COUNT \
  --max-removal-percent APPROVED_PERCENT \
  --allow-unattended-destructive
```

## 2. Reconfigure Applying Webhook Receivers

`serve-webhook --apply` will not start unless all of the following are configured:

- `--yes`;
- a fixed `--network-id`;
- a non-empty inbound Basic Auth username and password.

The fixed network is an authorization boundary: an event naming another network is rejected rather than causing the receiver to follow event-controlled scope.

Use protected service environment variables for secrets. For example, an owner-readable service environment file can contain:

```text
FWD_HOST=https://fwd.app
FWD_USER=awssync-service@example.com
FWD_PASS=FORWARD_SERVICE_PASSWORD
AWSSYNC_WEBHOOK_BASIC_USERNAME=awssync
AWSSYNC_WEBHOOK_BASIC_PASSWORD=RECEIVER_SHARED_SECRET
```

Start the applying receiver with an explicit network and durable service-owned state path:

```bash
./bin/awssync serve-webhook \
  --network-id NETWORK_ID \
  --listen 0.0.0.0:8080 \
  --path /forward/snapshot-ready \
  --webhook-state-file /var/lib/awssync/webhook-state.json \
  --apply \
  --yes
```

Forward must send the same Basic Auth values. Create or update the named Forward webhook with matching credentials:

```bash
./bin/awssync configure-webhook \
  --network-id NETWORK_ID \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --test-webhook
```

`configure-webhook` updates the same named webhook when it already exists. Coordinate the Forward-side credential update with the receiver restart so the values match throughout the change.

### Webhook state file

Without `--webhook-state-file`, Go's user configuration directory is used: `$XDG_CONFIG_HOME/awssync/webhook-state.json`, normally `$HOME/.config/awssync/webhook-state.json` on Linux, and `$HOME/Library/Application Support/awssync/webhook-state.json` on macOS. Services should use an explicit path such as `/var/lib/awssync/webhook-state.json`.

Create the parent directory as service-owned and inaccessible to other users. The state file is atomically written with mode `0600`; preserve that mode during backup or manual recovery. Keep it on durable local storage, retain it across restarts, and do not point two daemon processes at the same file because there is no interprocess lock.

The file holds pending events, completed-event deduplication, snapshot watermarks, and dead-letter records. A failed event is attempted at most five times before moving to `dead_letter_events`. Alert on a nonzero `/healthz` `deadLetterDepth`; see [Webhook recovery](aws-account-sync-procedure.md#webhook-recovery) before redelivering or discarding an event.

## 3. Review Unattended Destructive Applies

An apply that removes or disables accounts is destructive. When it runs with `--yes`, from CI, or from another unattended context, it now refuses unless `--allow-unattended-destructive` is also present.

Do not add the flag merely to silence the error. Forward exposes no ETag, version, or other compare-and-swap token for cloud-account setup updates. `awssync` re-reads the setup immediately before PATCH and detects a change that happened earlier, but it cannot make the following full-state PATCH atomic. A UI or automation edit made between that GET and PATCH is overwritten deterministically by the reviewed payload.

Before authorizing unattended destruction:

1. Ensure `sync-accounts` is using a complete, independently reviewed manifest.
2. Serialize all writers to the Forward setup, including UI, Terraform, other `awssync` jobs, and webhook daemons.
3. Use a maintenance window or another operational control that prevents concurrent edits.
4. Keep `--max-removals` and `--max-removal-percent` narrowly bounded.
5. Retain the rollback artifact and result journal, and verify the Forward setup immediately after apply.

If those controls are not available, keep destructive applies interactive and omit `--yes`.

## Other One-Time Changes

### Approval digest changes once

The approval digest format changed so the same approval-relevant plan now has the same digest across independent invocations. Old stored digests do not match the new format. After upgrading, discard any saved pre-upgrade digest, generate and review a fresh dry plan once, and store the new digest if external automation records it. Later changes to the network, snapshot, baseline, target, policy, or classified change counts still change the digest as intended.

### Account IDs are strict

NQE account IDs must now be exactly 12 digits. Rows that the previous version tolerated may stop preflight or planning. Fix the query or source data first.

For an urgent additive NQE run, `--allow-malformed-rows` skips and reports malformed NQE rows, marks the observed inventory incomplete, and blocks using that inventory for removals. It does not relax `sync-accounts` manifest validation; reviewed manifests always require unique 12-digit IDs.

## After the Upgrade

1. Run an additive dry plan and confirm `removed_accounts` is empty.
2. Run `status --json`; expect `observation_atomic` to be `false` because the latest-processed and snapshot-list endpoints are separate reads.
3. Test the webhook through `configure-webhook --test-webhook`, then confirm `/healthz` reports the expected pending and dead-letter depths.
4. Check service logs and the apply result journal after the first apply.
5. Run a new Forward snapshot and verify representative accounts collect successfully.

Snapshot timestamps more than five minutes ahead of the `awssync` host clock are rejected. If the first plan fails with an invalid future timestamp, correct NTP/clock configuration on the host or Forward side rather than increasing the snapshot-age limit.
