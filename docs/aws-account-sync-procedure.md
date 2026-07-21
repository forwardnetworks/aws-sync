# AWS Account Sync Procedure

This guide explains how to keep a Forward AWS cloud setup aligned with AWS accounts that are added to or removed from an AWS Organization.

It is written for readers who may not work in AWS every day. It focuses on the practical setup, preflight checks, and safe use of `awssync`.

## Summary

Forward collects AWS by using configured credentials to read AWS network metadata. In multi-account setups, Forward still assumes a role in each collected account.

For many AWS accounts in the same AWS Organization, there are two separate requirements:

1. Forward must be able to discover the AWS account inventory from AWS Organizations.
2. Forward must be able to assume a collection role in every account that should be collected.

`awssync` automates the Forward-side account list update for existing setups. It also has a separate `discover-org` onboarding mode for new setups that Forward has not collected yet. Neither mode creates IAM roles in AWS or grants Forward access to new accounts by itself. New accounts become collectable only after the expected IAM role exists in those accounts and trusts Forward.

This workflow supports both Forward IAM role and IAM user/access-key multi-account setups. In both modes, the existing Forward setup must have `assumeRoleInfos` entries with role ARNs so `awssync` can derive the role name and generate role ARNs for newly discovered accounts.

Important separation:

- Use the default NQE sync path for an existing Forward AWS setup. That path uses Forward's collected data and can PATCH the setup after review.
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

One AWS account must be available for Forward to use as the Organizations discovery point. This is usually the AWS Organizations management account. A delegated administrator account can also work if it has the required Organizations permissions.

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

Complete these checks before running `awssync --apply`.

### 1. Confirm Forward Is Collecting the AWS Organization Discovery Account

In Forward, confirm the AWS setup includes the management account or the delegated discovery account.

This matters because account inventory comes from AWS Organizations. If Forward only collects a member account that cannot list the Organization, the script will not have the complete account list to sync.

Expected result: the latest processed Forward snapshot includes the AWS setup and shows AWS account inventory from the Organization.

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

`awssync` gets discovered AWS account rows from Forward NQE.

The tool defaults to an inline Forward NQE source query for AWS account discovery. That inline query returns `Cloud Setup ID` from `cloudAccount.cloudSetupId`, which is required when one network has multiple AWS setups. When exactly one `--setup-id` is selected, the inline query is parameterized with that setup ID so Forward can scope the query before returning rows. `--query-id` is optional and should only be used when support intentionally overrides that query.

If a saved query declares a String setup parameter, pass `--query-setup-param PARAM_NAME` with exactly one `--setup-id`. Do not pass this flag to a saved query that does not declare the parameter; Forward rejects extra NQE parameters.

Expected result: the query returns AWS account IDs, names, and setup identifiers when there is more than one Forward AWS setup in the network. The built-in saved report that only returns name, ID, type, email, and collected status is not enough to separate multiple AWS setups.

## Build the Tool

```bash
make build
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

`discover-org` uses AWS credentials only for discovery. It uses the AWS SDK default credential chain, or the profile named by `--aws-profile`, and checks:

- `organizations:DescribeOrganization`
- `organizations:ListAccounts`
- `organizations:ListParents`

If any of those calls returns access denied, fix AWS Organizations access before continuing. The account list would otherwise be incomplete.

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

If Forward credentials are supplied, `discover-org` also resolves the network, verifies that the setup name does not already exist, and fetches the Forward-generated AWS external ID:

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

To create the new setup through the Forward API after writing both JSON files:

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --host "$FWD_HOST" \
  --username "$FWD_USER" \
  --password "$FWD_PASS" \
  --network-id "$FWD_NETWORK_ID" \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --post \
  --yes
```

For static IAM key collection, do not assume the AWS discovery credentials are the collector credentials. Provide the collector key explicitly:

```bash
export AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY='collector-secret'

AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --host "$FWD_HOST" \
  --username "$FWD_USER" \
  --password "$FWD_PASS" \
  --network-id "$FWD_NETWORK_ID" \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --credential-mode static-keys \
  --collector-access-key-id AKIA... \
  --post \
  --yes
```

If `--credential-mode static-keys` is used without `AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY` or `--collector-secret-access-key`, the create payload is still written, but it contains a placeholder password and `create_payload_ready` is `false`. That file is useful for review but should not be POSTed until the secret is supplied.

Do not use `discover-org` for a setup that already exists. Use the NQE sync path below so Forward's collected data, regions, proxy settings, and stored credentials remain the source of truth.

### Optional Terraform Bootstrap

For new AWS Organizations onboarding, prefer the Forward Terraform provider as the native IaC workflow. The provider can fetch Forward's external ID, read AWS Organizations, and create or update the Forward AWS setup directly with `forward_aws_cloud_account`. It supports Forward assume-role, static-key, and collector instance-profile credential models.

Use the `examples/terraform` bootstrap examples below when you need AWS-side prerequisites for either the provider workflow or the `awssync discover-org` CLI fallback:

- `examples/terraform/aws-org-discovery-role`: creates an IAM role with Organizations read permissions for `discover-org`.
- `examples/terraform/forward-collection-role-stackset`: deploys the Forward collection role name into member accounts with CloudFormation StackSets.
- `examples/terraform/github-actions-discover-org`: creates a GitHub OIDC role so GitHub Actions can run `discover-org` without static AWS keys.

Example:

```bash
terraform -chdir=examples/terraform/aws-org-discovery-role init
terraform -chdir=examples/terraform/aws-org-discovery-role apply

terraform -chdir=examples/terraform/forward-collection-role-stackset init
terraform -chdir=examples/terraform/forward-collection-role-stackset apply
```

Then use the StackSet role name with `discover-org`:

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --setup-id AWS-PROD \
  --role-name "$(terraform -chdir=examples/terraform/forward-collection-role-stackset output -raw role_name)" \
  --collect-region us-east-1 \
  --external-id Org:12345
```

Static-key collection through Terraform requires protected encrypted state because Terraform stores sensitive values in state. If the collector secret must stay out of Terraform state, use `awssync discover-org` and pass `AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY` from runtime secret storage.

## Run a Dry Plan

Start without `--apply`. This writes the planned PATCH payload to disk but does not update Forward.

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

Use `--format human` for an easier scan of checks and setup summaries:

```bash
./bin/awssync --max-snapshot-age 24h --format human
```

Then review the summary and payload:

- `selected_setup_ids`: setup IDs included in this run (useful when defaults are inferred).
- `planned_setups` (setup list sections): per-setup added/removed counts and OU visibility messages.

Review the JSON summary printed by the command:

- `fetched_item_count`: number of AWS account rows returned by NQE.
- `planned_setup_count`: number of Forward AWS setups that can be patched.
- `skipped_setup_count`: number of setups skipped because required metadata was missing.
- `configured_account_count`: number of accounts currently configured in Forward for a setup.
- `nqe_account_row_count`: number of AWS account rows returned by NQE for a setup.
- `nqe_candidate_row_count`: number of uncollected candidate accounts visible in NQE for a setup.
- `nqe_org_unit_row_count`: rows where NQE exposed AWS `organizationalUnitIds`. This is useful supporting evidence when present, but it can be zero for valid AWS Organizations where accounts are directly under the root.
- `planned_payload_account_count`: number of accounts planned for the PATCH payload.
- `added_accounts`: accounts that will be added to the Forward setup.
- `removed_accounts`: accounts that would be removed from the Forward setup.
- `unchanged_account_count`: accounts already present and still discovered.
- `candidate_check`: whether uncollected candidate accounts were visible in the snapshot. If none are visible, verify the management or delegated discovery account before applying removals.
- `organization_discovery_signal`: whether an Organization-level signal was visible for the setup (`visible_candidates`, `visible_ou_ids`, `visible_candidates_and_ou_ids`, or `no_org_signal`).
- `role_name`: IAM role name that will be used in each generated role ARN.
- `external_id_configured`: whether the normal sync payload preserves an External ID from the existing setup.
- `payload_sha256`: fingerprint of the payload written to disk.
- `manual_output`: optional path of setup-keyed manual payload for UI drag-and-drop.
- `manual_payload_sha256`: fingerprint of the manual payload written to disk.
- `manual_payloads`: map keyed by setup ID containing the planned `assumeRoleInfo` entries for manual drag-and-drop workflows.
- `patched`: should be `false` in a dry plan.

Then review `aws_sync_payload.json`. Confirm:

- Setup IDs are correct.
- Account IDs are expected 12-digit AWS account IDs.
- Account names look correct.
- Role ARNs use the intended role name.
- External ID matches the existing setup. Use the separate `external-id` command below when intentionally adding, replacing, or clearing it.
- Regions and proxy settings match the existing Forward setup.
- The PATCH payload does not include access keys or secrets; those stored credentials remain unchanged in Forward.
- Removed accounts are expected. If removals are not expected, stop and inspect the Forward snapshot and NQE query before applying.

If `--manual-output` is used, also confirm that manual payload file by opening it and verifying:

- Setup keys match `selected_setup_ids`.
- Each setup value is an array of account records with generated role ARNs and external IDs (if configured).

## Add a Customer-Defined External ID to an Existing Setup

This is a separate, one-time hardening change, not a prerequisite for AWS Organizations discovery. It is supported for an existing IAM user/access-key setup: Forward keeps using the stored IAM user credentials, but includes the configured External ID when it calls `sts:AssumeRole` for each target account.

Choose one customer-defined value per Forward AWS setup. Use the same value in Forward and in every target role trust policy for that setup. External IDs are not passwords, but use an unguessable, customer-specific value and do not reuse it across unrelated customers.

Use the dedicated `external-id` command rather than the normal NQE synchronization path. It reads the existing Forward setup directly, preserves its account list, role ARNs, regions, and proxy settings, and changes only the External ID on each `assumeRoleInfos` entry. It does not depend on NQE account discovery or a new snapshot.

First run a dry plan:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --format human
```

Review the prior-state fields and confirm every entry in `aws_external_id_payload.json` contains the intended `externalId`. The command requires exactly one setup and either `--value VALUE` or `--clear`; without `--apply`, it writes the payload but does not modify Forward. It does not change or expose the setup's stored IAM access key or secret.

Prepare the matching collection-role trust policy change for each target AWS account, but do not make the condition mandatory until the Forward payload has been applied and tested. For an IAM user in the connectivity account, the trust statement has this form:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustForwardCollectorUser",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<CONNECTIVITY_ACCOUNT_ID>:user/forward-collector"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "customer-defined-value"
        }
      }
    }
  ]
}
```

Apply the reviewed Forward payload before making the condition mandatory in AWS. AWS can receive an External ID on `AssumeRole` even while the existing trust statement does not yet require one, which makes it possible to stage the change without intentionally breaking collection:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --value customer-defined-value \
  --output aws_external_id_payload.json \
  --apply \
  --yes
```

Run a Forward snapshot and verify one representative account still collects. Then roll out the matching trust-policy condition with the existing StackSet, Terraform module, or account-vending automation. Test the representative account again before enforcing it everywhere. After this one-time PATCH stores the new value, later normal syncs read and preserve it without rerunning `external-id`.

An `sts:AssumeRole` failure after the trust-policy rollout usually means the trust policy principal or `sts:ExternalId` value does not exactly match the Forward setup payload.

To roll back intentionally, first remove the mandatory External ID condition from the affected role trust policies, then dry-run and apply the clear operation:

```bash
./bin/awssync external-id \
  --setup-id AWS-PROD \
  --clear \
  --output aws_external_id_clear_payload.json

./bin/awssync external-id \
  --setup-id AWS-PROD \
  --clear \
  --output aws_external_id_clear_payload.json \
  --apply \
  --yes
```

The clear payload omits `externalId` from every `assumeRoleInfos` entry, which stores it as null in Forward. Test a representative account again after the rollback.

## Run Preflight Checks

`preflight` performs read-only checks and prints a JSON readiness report.

```bash
./bin/awssync preflight \
  --max-snapshot-age 24h \
  --max-removals 10 \
  --max-removal-percent 5
```

Expected result: `ready` is `true`, `nqe_aws_accounts` passes, `patch_plan` passes, and `account_removals` either passes or is understood and approved.

If `management_account_discovery` fails, the snapshot did not show any uncollected AWS account candidates. That can happen when the AWS Organization has no undiscovered accounts, but it can also mean Forward is not collecting the management or delegated discovery account. Do not apply account removals in that state unless AWS Organizations discovery has been independently verified and `--allow-no-candidates` is intentional.

`aws_organizations_evidence` reports if the plan has either candidate visibility or OU ID visibility for each selected setup. In multi-setup runs, the check lists the setup IDs that lack this signal. Treat both as supporting evidence only. The safer destructive-sync guard is:

- `account_removals` requires `--allow-removals`.
- `removal_blast_radius` confirms the aggregate count and per-setup percentage remain within the operator-supplied ceilings.
- `management_account_discovery` fails: add `--allow-no-candidates` only after confirming discovery is complete.
- `aws_organizations_evidence` fails: add `--allow-no-org-evidence` only after independent verification that Forward has complete AWS Organizations visibility for that setup.

## Apply the Sync

After the dry plan is reviewed, run with `--apply`.

```bash
./bin/awssync \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --apply \
  --yes
```

Expected result: the command prints `patched_setup_count` greater than zero and each patched setup shows `patched: true`.

If the plan includes account removals, `--apply` fails unless `--allow-removals` is included. Use that flag only after reviewing `removed_accounts`.

For an approved removal, also set both blast-radius ceilings. `--max-removals` applies to the total across every selected setup, while `--max-removal-percent` applies independently to each setup's current configured-account count:

```bash
./bin/awssync \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --apply \
  --yes \
  --allow-removals \
  --max-removals 10 \
  --max-removal-percent 5
```

Choose limits from the reviewed plan, leaving enough room only for the approved account IDs. The command stops before any PATCH if either ceiling is exceeded. The same flags are enforced by `sync-accounts`, `apply-plan`, and webhook-driven apply runs.

If the plan includes account removals and no uncollected candidate accounts are visible, `--apply` also requires `--allow-no-candidates`. Use that flag only after confirming the management or delegated discovery account is collected and AWS Organizations discovery is working.

If the plan includes account removals and the same setup has neither candidate rows nor OU rows visible, `--apply` also requires `--allow-no-org-evidence`. Use that flag only after an independent validation that the setup is collecting from the expected AWS Organization.

To apply the exact reviewed payload file later without recomputing the plan:

```bash
./bin/awssync apply-plan \
  --plan aws_sync_payload.json \
  --yes
```

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

Add `--allow-removals` only when the reviewed plan contains expected removals.

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

If a new account appears in the Forward setup but fails collection, the most likely cause is missing or incorrect IAM role setup in that AWS account.

## Ongoing Automation

Run `awssync` on a schedule or after AWS account lifecycle events.

The recommended automation policy is to allow routine additions while keeping removals review-gated. Run scheduled automation without `--allow-removals`; a plan containing removals will stop before changing Forward. Treat any nonzero exit as an alert requiring operator review. Retain the JSON plan, its `payload_sha256`, and the `.applied.json` audit copy from successful applies according to the customer's audit policy. After an operator verifies the account lifecycle in AWS and reviews `removed_accounts`, apply the reviewed plan with explicit removal approval and narrow `--max-removals` and `--max-removal-percent` ceilings.

Recommended sequence:

1. AWS account is created or closed.
2. Automation creates or removes the Forward collection IAM role.
3. Forward runs a snapshot that can discover the updated Organization account inventory.
4. `awssync` runs against that processed snapshot or latest processed snapshot.
5. Forward runs the next collection with the updated account list.

For event-driven workflows, `awssync serve-webhook` can receive Forward `SNAPSHOT_READY` events and run the sync against the exact snapshot from the event.

Start the receiver:

```bash
./bin/awssync serve-webhook \
  --listen :8080 \
  --path /forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --apply \
  --yes
```

Create the Forward webhook through the Forward API:

```bash
./bin/awssync configure-webhook \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --test-webhook
```

Forward webhooks use Basic Auth credentials when credentials are configured. The `--webhook-basic-username` and `--webhook-basic-password` values on `configure-webhook` must match the receiver values on `serve-webhook`.

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
- Start in dry-run mode first, without `--apply`, and confirm webhook delivery and payload generation.
- Add `--apply --yes` only after dry-run output is reviewed.
- Use `--allow-removals` only after an operator reviews planned removals.
- Use `--allow-no-candidates` only after confirming management or delegated discovery is working.
- Use `--allow-no-org-evidence` only after independent verification that AWS Organizations discovery remains complete.
- Send service logs to the normal log collection system.

Linux systemd command example:

```ini
ExecStart=/usr/local/bin/awssync serve-webhook --listen 0.0.0.0:8080 --apply --yes
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

Fix: run `preflight`, verify `management_account_discovery`, and confirm the AWS Organizations access check. Do not approve removals from this state unless the account list is confirmed complete.

### Webhook Does Not Trigger Sync

Likely causes:

- The Forward webhook URL is not reachable from the Forward app server.
- Forward SaaS is pointed at a private or VPN-only receiver URL.
- Basic Auth values in Forward do not match the receiver.
- The webhook is not scoped to the intended network.

Fix: run `configure-webhook --test-webhook`, check receiver logs, and confirm `/healthz` is reachable from the same network path Forward will use.

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

## Summary

AWS account sync has two layers:

1. AWS Organizations tells Forward which accounts exist.
2. IAM roles in each AWS account allow Forward to collect those accounts.

`awssync` automates layer 1 into Forward's configured account list. Layer 2 is still required in AWS: every account must have the expected IAM role and trust policy. For IAM user/access-key setups, the stored credential must also be allowed to assume those roles. This is why the first setup step is verifying management-account or delegated-account Organizations visibility before running the script.
