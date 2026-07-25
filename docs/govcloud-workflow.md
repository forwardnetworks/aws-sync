# AWS GovCloud Account Workflow

Use this workflow for AWS GovCloud (US) accounts, including customers that cannot use AWS Organizations.

AWS Organizations is available in GovCloud, but a GovCloud organization is independent from a commercial AWS organization. Its Organizations control plane is in `us-gov-west-1`. Forward's regular AWS collection pipeline can query Organizations using the GovCloud setup credentials and primary region.

There are two supported synchronization paths:

1. **GovCloud Organizations + Forward NQE** can add and re-enable observed accounts when the customer grants read access to the GovCloud organization. It never removes accounts.
2. **Reviewed account manifest** is the authoritative path for lifecycle removals and the fallback for standalone accounts or customers that cannot grant Organizations access.

Do not treat a successfully collected GovCloud region as proof that Organizations discovery succeeded. Resource collection and organization inventory are separate checks.

## Credential Model

For a self-managed collector running in GovCloud, prefer its EC2 instance profile. Give that instance-profile role permission to assume the consistent collection role in every target GovCloud account.

The generated target role ARNs must use the GovCloud partition:

```text
arn:aws-us-gov:iam::111111111111:role/ForwardReadOnlyAccess
```

Do not use `arn:aws:iam` for GovCloud accounts. If a customer-defined External ID is required, configure the identical value in Forward's per-account entries and in every target role trust policy.

## Path A: Regular Forward Organizations Discovery

Use this path when the configured GovCloud account is an Organizations management account or has the required delegated/read access.

The regular Forward collector uses these APIs:

- `organizations:DescribeAccount`
- `organizations:ListAccounts`
- `organizations:ListRoots`
- `organizations:ListOrganizationalUnitsForParent`

Configure at least `us-gov-west-1` in the Forward AWS setup. Run a Forward connectivity test and a new snapshot, then run read-only preflight:

```bash
./bin/awssync preflight \
  --network-id NETWORK_ID \
  --setup-id GOVCLOUD_SETUP \
  --max-snapshot-age 24h \
  --format human
```

Preflight should confirm all of the following before additive synchronization:

- the setup's role ARNs consistently use `arn:aws-us-gov`;
- the configured collection regions are GovCloud regions;
- the current snapshot returns AWS accounts for the selected setup;
- Forward NQE exposes the expected observed accounts and, when available, Organizations metadata such as Organizational Unit IDs.

An account directly under the organization root may have no OU ID. More importantly, NQE is observed inventory rather than a configured-account manifest: authorization failures, collection failures, organization scope, and transient errors can all make an account absent. NQE absence therefore never produces a GovCloud removal.

If preflight is ready, generate and review the additive payload normally. For any lifecycle removal, switch to Path B.

## Path B: Manual Account Manifest

Use this path for every lifecycle removal, and when the customer has standalone GovCloud accounts, Organizations is unavailable by policy, or Forward cannot see the GovCloud organization.

Create a reviewed JSON file containing the complete authoritative account inventory:

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

Account IDs must contain exactly 12 digits and must be unique. Keep real customer manifests in the customer's approved secret/configuration system; do not commit them to this repository.

### Create a New Forward Setup

Generate review artifacts without changing Forward:

```bash
./bin/awssync onboard-accounts \
  --accounts-file govcloud-accounts.json \
  --partition aws-us-gov \
  --credential-mode instance-profile \
  --setup-id GOVCLOUD_SETUP \
  --role-name ForwardReadOnlyAccess \
  --collect-region us-gov-west-1 \
  --external-id CUSTOMER_DEFINED_VALUE \
  --output govcloud-create.json \
  --manual-output govcloud-fwd-accounts.json \
  --format human
```

Verify that every `roleArn` begins with `arn:aws-us-gov:iam::`. To create the setup after review, supply the Forward connection settings and add `--post --yes`. Without `--post`, this command only writes files.

### Update an Existing Forward Setup

First generate a dry plan from the complete manifest:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id GOVCLOUD_SETUP \
  --accounts-file govcloud-accounts.json \
  --output govcloud-sync-plan.json \
  --format human
```

The report prints the exact added and removed account IDs. A dry run never patches Forward.

If there are no removals, apply the reviewed plan with:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id GOVCLOUD_SETUP \
  --accounts-file govcloud-accounts.json \
  --output govcloud-sync-plan.json \
  --apply \
  --yes
```

If removals are intentional, the apply is blocked unless the operator also supplies `--allow-removals`:

```bash
./bin/awssync sync-accounts \
  --network-id NETWORK_ID \
  --setup-id GOVCLOUD_SETUP \
  --accounts-file govcloud-accounts.json \
  --output govcloud-sync-plan.json \
  --apply \
  --allow-removals \
  --max-removals 5 \
  --max-removal-percent 5 \
  --allow-unattended-destructive \
  --yes
```

Set the ceilings to the reviewed change, not to the full account population. `--max-removals` limits the total removals in the run, and `--max-removal-percent` prevents a single setup from losing more than the approved percentage. Exceeding either value blocks before PATCH. `--allow-unattended-destructive` is also required here because `--yes` skips the human confirmation and Forward provides no atomic compare-and-swap token. For a human-attended removal, omit both `--yes` and `--allow-unattended-destructive` and type `apply` after reviewing the preview.

After any update, run a Forward connectivity test for representative accounts, run a new snapshot, and inspect per-account collection errors.

Do not use `apply-plan` to bypass these source checks. `apply-plan` reloads the current Forward setup before patching and refuses GovCloud account removals; rerun `sync-accounts` with the reviewed manifest instead.

## When This Is a Forward Product Issue

Escalate as a possible Forward collection enhancement or defect only when all of these are true:

1. Forward successfully collects GovCloud resources with the configured GovCloud credential path.
2. The caller is in the expected GovCloud organization and can run the four Organizations APIs above directly.
3. The Forward setup includes `us-gov-west-1` and uses GovCloud role ARNs.
4. A fresh Forward snapshot still reports no organization member accounts or OU inventory.
5. Collector logs show that the Organizations request used the GovCloud context, or show a reproducible failure from that request.

Capture the setup ID, snapshot ID, collector version, Organizations error, configured regions, and redacted role ARN partition. Do not include secrets or full customer manifests in the issue.

AWS references:

- [AWS Organizations in AWS GovCloud (US)](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-organizations.html)
- [Region support for AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/region-support.html)
