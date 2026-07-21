# aws-sync

`awssync` discovers AWS accounts through Forward NQE, builds one PATCH payload per existing AWS cloud setup, writes those payloads to disk, and can optionally PATCH them back into Forward.
It also has a `discover-org` onboarding mode that reads AWS Organizations directly, writes the Forward UI `fwd_accounts_data` upload JSON, and writes the Forward create-setup POST JSON for new AWS setups.

For new AWS Organizations onboarding, the native IaC workflow is now the Forward Terraform provider. Use Terraform when the organization can use a stable Forward collection role name across accounts and one of Forward's supported credential models: Forward assume-role, static collector keys, or collector instance profile. Use `awssync discover-org` when you need manual JSON files, a break-glass workflow, or static-key collector payloads that should stay outside Terraform state.

The repository is structured like `awsfilter`: Cobra/Viper CLI entrypoint, raw API client package, and isolated run/planning logic with tests.

## What it does

1. Calls `POST /api/nqe?networkId={networkId}` and pages through AWS account rows using the selected NQE query. When `--snapshot-id` is provided, the NQE run is pinned to that snapshot.
2. Calls `GET /api/networks/{networkId}/cloudAccounts` to load existing AWS setup metadata.
3. Groups discovered accounts by setup ID when the query includes that column.
4. Rebuilds `assumeRoleInfos` for each eligible AWS setup using the existing role name, optional external ID, proxy server ID, and region timestamps.
5. Writes the full PATCH payload map to JSON.
6. Optionally writes setup-keyed manual JSON for UI drag-and-drop workflows.
7. Optionally calls `PATCH /api/networks/{networkId}/cloudAccounts/{setupId}` for each planned setup.

`discover-org` is separate. It is for a new Forward AWS setup that is not onboarded yet, and it does not PATCH existing setups. It uses the AWS SDK default credential chain or `--aws-profile` to call `organizations:DescribeOrganization`, `organizations:ListAccounts`, and `organizations:ListParents`, then writes:

- `fwd_accounts_data_<timestamp>.json`: flat account array for the Forward UI drag-and-drop flow.
- `aws_create_payload_<timestamp>.json`: body for `POST /api/networks/{networkId}/cloudAccounts`.

Terraform examples for AWS-side prerequisites live in [examples/terraform](examples/terraform). They create AWS Organizations read roles, Forward collection roles through StackSets, and an optional GitHub OIDC role for running `discover-org` without long-lived AWS keys. For a fully Terraform-native Forward onboarding workflow, use the Forward Terraform provider's `forward_aws_assume_role_external_id`, `forward_aws_organization_accounts`, and `forward_aws_cloud_account` resources/data sources.

The Forward collection IAM role name must be the same in every AWS account that should be collected. `awssync` uses the role name from the existing Forward AWS setup as the template for generated role ARNs.

Both Forward IAM role and IAM user/access-key multi-account setups are supported. In IAM user/access-key mode, Forward still uses the configured access key to assume the per-account role ARNs in `assumeRoleInfos`; the PATCH updates those account entries and leaves stored credentials unchanged.

An existing setup can add, replace, or clear its per-account External ID without changing those stored credentials. Use the dedicated one-time migration command; its dry run reads the current setup directly and does not depend on NQE or a new snapshot:

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

The value is written to every existing `assumeRoleInfos` entry for that setup. Review and apply the Forward payload first, test a representative account, and then update the target-role trust policies to require the identical value. After the migration PATCH, normal syncs preserve the stored External ID without rerunning this command. For rollback, relax or remove the mandatory `sts:ExternalId` trust-policy condition first, confirm the role can still be assumed, and only then apply `external-id --clear`. Stored IAM access keys and secrets are not included in or changed by the PATCH.

## Procedure

For an end-to-end flow diagram showing connection types and required permissions, see [AWS Account Sync End-to-End Flow](docs/architecture-flow.md).

For a short quick start, see [AWS Account Sync Quick Start](docs/quick-start.md).

For the full procedure, including AWS Organizations prerequisites, management-account or delegated-account discovery checks, IAM role checks, dry-run review, apply, and post-apply validation, see [AWS Account Sync Procedure](docs/aws-account-sync-procedure.md).

For GovCloud Organizations and standalone-account workflows, including collector instance-profile credentials, GovCloud ARN validation, a reviewed account-manifest fallback, and stricter removal gates, see [AWS GovCloud Account Workflow](docs/govcloud-workflow.md).

## Build

```bash
make build
```

## Install a Release

Prefer the tarball because it preserves the executable bit. Download the tarball and checksum manifest for the required platform, verify both the checksum and GitHub build provenance, then extract it:

```bash
VERSION=v2.1.2
PLATFORM=linux-amd64

gh release download "$VERSION" \
  --repo forwardnetworks/aws-sync \
  --pattern "awssync-${PLATFORM}.tar.gz" \
  --pattern sha256sums.txt

grep "  awssync-${PLATFORM}.tar.gz$" sha256sums.txt | sha256sum -c -
gh attestation verify "awssync-${PLATFORM}.tar.gz" \
  --repo forwardnetworks/aws-sync \
  --signer-workflow forwardnetworks/aws-sync/.github/workflows/release.yml

tar -xzf "awssync-${PLATFORM}.tar.gz"
./"awssync-${PLATFORM}" --help
```

On macOS, use `PLATFORM=darwin-amd64` or `PLATFORM=darwin-arm64` and replace `sha256sum -c -` with `shasum -a 256 -c -`. A raw binary downloaded directly from GitHub may need `chmod +x`; the tarball does not.

## Usage

Set common inputs through environment variables:

```bash
export FWD_HOST=https://fwd.app
export FWD_USER=you@example.com
export FWD_PASS='secret'
export FWD_NETWORK_ID=NETWORK_ID
```

Use the Forward base URL for `FWD_HOST`; it can be SaaS or an on-prem Forward instance.

Plan and write payloads only:

```bash
./bin/awssync
```

Run preflight checks before planning or applying:

```bash
./bin/awssync preflight \
  --max-snapshot-age 24h
```

Use readable output with:

```bash
./bin/awssync preflight --format human
./bin/awssync --format human
```

`--format` accepts `json` (default) or `human`.

Use `--manual-output` if you also want UI-friendly drag-and-drop JSON:

```bash
./bin/awssync \
  --manual-output aws_sync_manual_payload.json
```

Discover an AWS Organization before Forward has collected it:

Prefer the Forward Terraform provider for native IaC onboarding. This CLI mode is best for manual review files, break-glass onboarding, or environments that cannot yet use the provider.

```bash
AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --collect-region us-west-2 \
  --external-id Org:12345
```

If Forward credentials are supplied, `discover-org` can fetch the Forward-generated AWS external ID and validate that the setup name does not already exist:

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

To create the new Forward setup through the API after writing both JSON files, add `--post --yes`. For static IAM key collection, use `--credential-mode static-keys --collector-access-key-id KEY_ID` and provide the secret through `AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY`; otherwise the create payload contains a placeholder and is not POST-ready.

Optional Terraform bootstrap for the CLI fallback:

```bash
terraform -chdir=examples/terraform/aws-org-discovery-role init
terraform -chdir=examples/terraform/aws-org-discovery-role apply

terraform -chdir=examples/terraform/forward-collection-role-stackset init
terraform -chdir=examples/terraform/forward-collection-role-stackset apply
```

Apply the generated payloads back into Forward:

```bash
./bin/awssync \
  --max-snapshot-age 24h \
  --apply \
  --yes
```

When interactive, `--apply` without `--yes` now performs a dry plan pass first and then prompts:

```text
Planned changes: add=2 remove=0.
Type 'apply' to continue:
```

If the plan removes accounts from a Forward setup, `--apply` fails unless `--allow-removals` is also provided.
Use `--max-removals` to cap the aggregate removal count across all selected setups and `--max-removal-percent` to cap each setup independently. Both are optional, apply-time safety ceilings; a value of `0` disables that limit.
If removals are included and no uncollected candidate rows are visible, add `--allow-no-candidates` only after confirming AWS Organizations discovery.
If removals are included and there is no candidate or Organizational Unit signal, add `--allow-no-org-evidence` only after independent discovery verification.
In a run with multiple `--setup-id` values, this is enforced per setup and the check output includes the setup IDs that are missing signals.

For example, an approved removal run can still be limited to no more than 10 accounts overall and no more than 5% of any setup:

```bash
./bin/awssync \
  --apply \
  --yes \
  --allow-removals \
  --max-removals 10 \
  --max-removal-percent 5
```

Apply a reviewed payload file without recomputing the plan:

```bash
./bin/awssync apply-plan \
  --plan aws_sync_payload.json \
  --yes
```

Run the planner against a specific snapshot:

```bash
./bin/awssync \
  --snapshot-id SNAPSHOT_ID
```

Command-line flags are also supported for one-off runs:

```bash
./bin/awssync \
  --host https://fwd.app \
  --username you@example.com \
  --password 'secret' \
  --network-id NETWORK_ID
```

`AWSSYNC_*` environment variables are also accepted. `FWD_USERNAME` and `FWD_PASSWORD` are accepted for compatibility with the original script.

`--query-id` is optional. By default, the tool sends an inline Forward NQE source query that includes `cloudAccount.cloudSetupId` as `Cloud Setup ID`, which is required to separate accounts when a network has multiple AWS setups. When exactly one `--setup-id` is selected, the inline query is parameterized with that setup ID so Forward can scope the query before returning rows. Use `--query-id` only when intentionally overriding that query; saved query overrides must also return `Cloud Setup ID` for multi-setup sync.

If a saved query declares a String setup parameter, pass `--query-setup-param PARAM_NAME` with exactly one `--setup-id`:

```bash
./bin/awssync preflight \
  --query-id Q_... \
  --query-setup-param setupId \
  --setup-id AWS_SETUP_ID
```

`--network-id` can be omitted when the Forward user can see exactly one network. If a terminal is attached and multiple networks are visible, the CLI shows a numbered picker and accepts either the menu number or the network ID. Noninteractive runs should pass `--network-id` explicitly.

`--setup-id` can be omitted when the network has exactly one eligible AWS setup.
If the network has multiple AWS setups:
- interactive terminal: a setup picker is shown and accepts menu numbers or case-insensitive setup IDs.
- non-interactive: `--setup-id` must be provided (repeat for multiple setups) or the command exits with a selection error.

The selected setup IDs are shown in `selected_setup_ids` in JSON/human output.

If the network has multiple AWS setups and only one should be synchronized, scope the run with `--setup-id`:

```bash
./bin/awssync \
  --setup-id AWS_SETUP_ID
```

Repeat `--setup-id` to sync more than one setup.

Example output:

```json
{
  "host": "https://fwd.app",
  "network_id": "NETWORK_ID",
  "query_override": false,
  "output": "/path/to/aws_sync_payload.json",
  "manual_output": "/path/to/aws_sync_manual_payload.json",
  "payload_sha256": "91f9c6...",
  "manual_payload_sha256": "f5b9d4...",
  "manual_payloads": {
    "collect_aws": [
      {
        "accountId": "111111111111",
        "accountName": "acct-a",
        "roleArn": "arn:aws:iam::111111111111:role/ForwardRole",
        "externalId": "Org:12345",
        "enabled": true
      }
    ]
  },
  "apply": false,
  "fetched_item_count": 25,
  "planned_setup_count": 2,
  "patched_setup_count": 0,
  "skipped_setup_count": 0,
  "planned_setups": [
    {
      "setup_id": "collect_aws",
      "role_name": "ForwardRole",
      "org_id": 12345,
      "external_id_configured": true,
      "proxy_server_id": "proxy-1",
      "regions": ["us-east-1", "us-west-2"],
      "configured_account_count": 20,
      "nqe_account_row_count": 21,
      "nqe_candidate_row_count": 1,
      "nqe_org_unit_row_count": 0,
      "organization_discovery_signal": "visible_candidates",
      "planned_payload_account_count": 21,
      "added_accounts": [
        {"account_id": "222222222222", "account_name": "new-account"}
      ],
      "unchanged_account_count": 19,
      "patched": false
    }
  ]
}
```

Manual payload example:

```json
{
  "collect_aws": [
    {
      "accountId": "111111111111",
      "accountName": "acct-a",
      "roleArn": "arn:aws:iam::111111111111:role/ForwardRole",
      "externalId": "Org:12345",
      "enabled": true
    }
  ]
}
```

`discover-org` manual upload example:

```json
[
  {
    "id": "111111111111",
    "name": "acct-a",
    "roleArn": "arn:aws:iam::111111111111:role/ForwardRole",
    "externalId": "Org:12345",
    "errorMsg": null
  }
]
```


Check snapshot state directly from the tool:

```bash
./bin/awssync status
```

Wait for a snapshot to finish processing:

```bash
./bin/awssync wait \
  --snapshot-id SNAPSHOT_ID
```

Run as a webhook receiver for Forward `SNAPSHOT_READY` events:

```bash
./bin/awssync serve-webhook \
  --listen :8080 \
  --path /forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --apply \
  --yes
```

Webhook mode requires `networkId` and `snapshotId` in the incoming JSON body. The receiver pins the NQE run to that exact snapshot so newly processed snapshots do not race with the webhook event that triggered the sync.

Create the Forward webhook with API access:

```bash
./bin/awssync configure-webhook \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --webhook-basic-username awssync \
  --webhook-basic-password RECEIVER_SHARED_SECRET \
  --test-webhook
```

`configure-webhook` creates the webhook when missing and updates the same named webhook when it already exists. To scope webhook-triggered syncs to one or more AWS setups, pass `--setup-id`; the setup IDs are added to the receiver URL and shown in run/preflight output. To create one webhook per setup, also pass `--webhook-per-setup`.

```bash
./bin/awssync configure-webhook \
  --webhook-url https://awssync.example.com/forward/snapshot-ready \
  --setup-id AWS \
  --setup-id AWS-SANDBOX \
  --webhook-per-setup
```

If Forward is SaaS, the webhook URL must be reachable from Forward SaaS over the internet. A localhost, RFC1918, or private URL will not work unless the receiver is exposed through an approved public endpoint, reverse proxy, or tunnel. For on-prem Forward, the URL only needs to be reachable from the Forward app server.

### Webhook Service Install

For ongoing webhook use, run `serve-webhook` as a service on a host that can reach Forward and that Forward can reach on the webhook URL.

Use an environment file for Forward credentials and receiver settings:

```bash
FWD_HOST=https://fwd.app
FWD_USER=you@example.com
FWD_PASS=secret
AWSSYNC_WEBHOOK_BASIC_USERNAME=awssync
AWSSYNC_WEBHOOK_BASIC_PASSWORD=receiver-shared-secret
```

Linux systemd example:

```ini
[Unit]
Description=Forward AWS account sync webhook receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/awssync/awssync.env
ExecStart=/usr/local/bin/awssync serve-webhook --listen 0.0.0.0:8080 --apply --yes
Restart=on-failure
RestartSec=10
User=awssync
Group=awssync

[Install]
WantedBy=multi-user.target
```

For temporary SaaS testing, a short-lived tunnel such as `trycloudflare` can expose the receiver. Do not use account-less tunnels for production.

## Notes

- The default query is the Forward platform source query for AWS account discovery.
- `--query-id` is an optional override for support/debug workflows. Multi-setup sync requires the query to return `Cloud Setup ID`.
- `--query-setup-param` sends the single selected `--setup-id` into a parameterized saved query. Use it only when the saved query declares that String parameter.
- Forward webhook configuration uses Basic Auth credentials; `serve-webhook` supports the same Basic Auth model.
- Payloads are always written to disk before any PATCH occurs.
