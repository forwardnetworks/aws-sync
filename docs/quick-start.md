# AWS Account Sync Quick Start

Use `awssync` to update an existing Forward AWS setup when AWS Organization accounts are added or removed and Forward's collected NQE data is the source of truth.

For new AWS Organizations onboarding, prefer the Forward Terraform provider as the native IaC workflow. It supports Forward assume-role, static-key, and collector instance-profile credential models. Use `awssync discover-org` only when Forward has not onboarded that AWS Organization yet and you need manual JSON files, a break-glass create payload, or a static-key workflow that should stay outside Terraform state.

## Before You Start

- Forward must collect the AWS management account or a delegated account that can list AWS Organizations accounts.
- Each AWS account that Forward should collect must have the same Forward IAM role name.
- Forward IAM role and IAM user/access-key multi-account setups are supported.
- Run a dry plan first. Do not apply removals until the account list is reviewed.

Grant AWS Organizations read permissions only to the management or delegated discovery account used for inventory. Do not grant organization-wide permissions to every member role. Member accounts need the Forward collection policy and trust policy for `sts:AssumeRole`.

A cloud setup or snapshot can succeed while individual member accounts fail collection. Inspect per-account logs for role assumption, trust-policy, external-ID, or collection-permission errors.

## Set Forward Login

```bash
export FWD_HOST=https://fwd.app
export FWD_USER=you@example.com
export FWD_PASS='secret'
export FWD_NETWORK_ID=NETWORK_ID
```

Use the Forward URL for `FWD_HOST`.

`FWD_NETWORK_ID` is optional when your Forward user can see exactly one network. In an interactive terminal, the CLI can show a numbered network picker when more than one network is visible. Scripts and scheduled jobs should set `FWD_NETWORK_ID` or pass `--network-id`.

If the selected network has multiple AWS setups:
- interactive terminal: a setup picker is shown and accepts setup numbers or case-insensitive setup IDs.
- non-interactive: pass one or more `--setup-id` values; otherwise the command exits with a setup selection error.

## Check Readiness

```bash
./bin/awssync preflight --max-snapshot-age 24h --format human
```

Expected result: `ready` is `true`.

If `management_account_discovery` fails, confirm Forward is collecting the AWS management or delegated discovery account.

`nqe_org_unit_row_count` is helpful supporting evidence when it is nonzero, but it can be zero for valid AWS Organizations where accounts sit directly under the root. Do not use OU IDs as the only safety signal for removals.

If both `nqe_candidate_row_count` and `nqe_org_unit_row_count` are zero and removals are planned, review `--allow-no-org-evidence` before applying.

In multi-setup runs, `--allow-no-org-evidence` is required only for setup IDs that are missing both signals; preflight output shows the setup IDs in the failing check message.

## Create a Dry Plan

```bash
./bin/awssync --max-snapshot-age 24h --output aws_sync_payload.json --manual-output aws_sync_manual_payload.json
```

Review:

- `added_accounts`
- `removed_accounts`
- `role_name`
- `external_id_configured`
- `proxy_server_id`
- `regions`

If you need a manual fallback format for UI drag-and-drop, also review `aws_sync_manual_payload.json`:

- top-level keys are setup IDs
- each value is the list of `assumeRoleInfos` planned for that setup
- you can paste a single setup block into the Forward UI or use it as a reference before apply

Stop if removed accounts are unexpected.

## Add an External ID to an Existing IAM User Setup

This is a one-time change separate from the AWS Organizations setup checklist. To add a customer-defined External ID while keeping the existing IAM user/access-key credentials, use the dedicated command. It reads the existing setup directly, so it does not need NQE account discovery or a new snapshot:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --format human

./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --apply \
  --yes
```

Confirm the dry run reports the expected prior and target state and verify every generated account entry has the expected `externalId`. Apply the reviewed command and test one account. Then configure the identical `sts:ExternalId` condition in each target collection role trust policy, preferably through the existing StackSet or account-vending automation, and test again before broad rollout.

Run the command once per Forward AWS setup if different setups require different values. It does not replace or expose the IAM user's stored access key or secret. After the migration PATCH, later syncs preserve the stored External ID without rerunning it. To roll back intentionally, replace `--value VALUE` with `--clear`, review the dry run, and apply it.

## Discover Before Onboarding

Prefer the Forward Terraform provider for native IaC onboarding. Use this CLI path for a new Forward AWS setup when you need manual review artifacts or cannot use the provider. It reads AWS Organizations directly and never patches an existing Forward setup.

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --collect-region us-west-2 \
  --external-id Org:12345
```

Outputs:

- `fwd_accounts_data_<timestamp>.json`: upload this in the Forward UI account import step.
- `aws_create_payload_<timestamp>.json`: POST body for `POST /api/networks/{networkId}/cloudAccounts`.

If Forward credentials are available, omit `--external-id`; the CLI fetches the Forward-generated external ID and checks that the setup name is not already used:

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --host "$FWD_HOST" \
  --username "$FWD_USER" \
  --password "$FWD_PASS" \
  --network-id "$FWD_NETWORK_ID" \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1
```

To create the setup from automation, add `--post --yes`. Static-key collection also needs `--credential-mode static-keys --collector-access-key-id KEY_ID` and `AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY`.

Terraform examples for AWS-side bootstrap are in `examples/terraform`. These are useful for the CLI fallback and for the provider workflow:

```bash
terraform -chdir=examples/terraform/aws-org-discovery-role init
terraform -chdir=examples/terraform/aws-org-discovery-role apply

terraform -chdir=examples/terraform/forward-collection-role-stackset init
terraform -chdir=examples/terraform/forward-collection-role-stackset apply
```

## Apply

```bash
./bin/awssync --max-snapshot-age 24h --output aws_sync_payload.json --apply --yes
```

If removals are expected:

```bash
./bin/awssync --max-snapshot-age 24h --output aws_sync_payload.json --apply --yes --allow-removals
```

If removals are expected and no uncollected candidate accounts are visible, also add `--allow-no-candidates` only after confirming AWS Organizations discovery is working.

If removals are expected and there is no candidate signal and no OU signal for a setup, also add `--allow-no-org-evidence` only after independent verification that Forward’s discovery account is still collecting a complete AWS Organization account list.

## Multiple AWS Setups

Preflight two selected setups:

```bash
./bin/awssync preflight \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --format human
```

Create a dry plan for the same setups:

```bash
./bin/awssync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json
```

Recompute and apply after reviewing the expected changes:

```bash
./bin/awssync \
  --setup-id AWS-PROD \
  --setup-id AWS-SANDBOX \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --apply \
  --yes
```

For one setup, pass a single `--setup-id AWS_SETUP_ID`. Repeat `--setup-id` for other setup combinations. Add `--allow-removals` only after reviewing and confirming every proposed removal.

When exactly one setup is selected, the default inline NQE query is parameterized by that setup ID to reduce returned rows. Multiple setup IDs are still separated by `Cloud Setup ID` in the NQE result.

For automation, run without `--allow-removals` so normal additions can proceed when no removals are planned. A removal plan stops the run and should be applied only after an operator confirms the account lifecycle in AWS.

## Troubleshoot Account State

Use AWS Organizations visibility together with the member account's `sts:AssumeRole` result:

| Visible in AWS Organizations | `sts:AssumeRole` | Action |
| --- | --- | --- |
| Yes | Succeeds | Keep the account configured. |
| Yes | Fails | Repair the member collection role, trust policy, external ID, or permissions. Do not remove the account. |
| No | Succeeds | Verify discovery scope and Organization membership. Do not remove based only on discovery. |
| No | Fails | Confirm whether the account was closed, removed, or moved. Remove only after independent confirmation; otherwise repair discovery or IAM. |

## Webhook Option

For event-driven sync, run the receiver:

```bash
./bin/awssync serve-webhook --listen 0.0.0.0:8080 --webhook-basic-username awssync --webhook-basic-password RECEIVER_SECRET --apply --yes
```

Then configure Forward:

```bash
./bin/awssync configure-webhook --webhook-url https://awssync.example.com/forward/snapshot-ready --webhook-basic-username awssync --webhook-basic-password RECEIVER_SECRET --test-webhook
```

For setup-scoped webhook sync, add `--setup-id SETUP_ID`. Repeat it for more than one setup, or add `--webhook-per-setup` to create one Forward webhook per setup.

For Forward SaaS, the webhook URL must be reachable from the internet.

## More Detail

See [AWS Account Sync Procedure](aws-account-sync-procedure.md) for the full procedure and troubleshooting guidance.
