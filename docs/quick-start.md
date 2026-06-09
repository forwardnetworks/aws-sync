# AWS Account Sync Quick Start

Use `awssync` to update a Forward AWS setup when AWS Organization accounts are added or removed.

## Before You Start

- Forward must collect the AWS management account or a delegated account that can list AWS Organizations accounts.
- Each AWS account that Forward should collect must have the same Forward IAM role name.
- Forward IAM role and IAM user/access-key multi-account setups are supported.
- Run a dry plan first. Do not apply removals until the account list is reviewed.

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

To sync one setup:

```bash
./bin/awssync --setup-id AWS_SETUP_ID --max-snapshot-age 24h
```

Repeat `--setup-id` for multiple setups.

When exactly one setup is selected, the default inline NQE query is parameterized by that setup ID to reduce returned rows. Multiple setup IDs are still separated by `Cloud Setup ID` in the NQE result.

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
