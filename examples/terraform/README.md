# Terraform Examples

These examples cover AWS-side prerequisites for AWS Organizations onboarding.

The native IaC workflow is the Forward Terraform provider: use these examples to prepare AWS access, then use the provider's `forward_aws_assume_role_external_id`, `forward_aws_organization_accounts`, and `forward_aws_cloud_account` resources/data sources to create or update the Forward AWS setup. The provider supports Forward assume-role, static-key, and collector instance-profile credential models.

`awssync discover-org` remains useful when you need manual JSON files, a break-glass POST payload, or a static-key collector workflow that should stay outside Terraform state.

## Examples

- `aws-org-discovery-role`: IAM role that lets a human, automation role, or GitHub Actions role read AWS Organizations account inventory.
- `forward-collection-role-stackset`: CloudFormation StackSet that deploys the Forward collection IAM role into member accounts.
- `github-actions-discover-org`: GitHub OIDC role for running `awssync discover-org` in GitHub Actions without long-lived AWS keys.

## Native IaC Flow

1. Apply the AWS Organizations read role in the management account or delegated administrator account.
2. Apply the collection-role StackSet to the target OU/root so every member account gets the same role name.
3. Use the Forward Terraform provider to read the organization and manage the Forward AWS setup.

```hcl
data "forward_aws_assume_role_external_id" "current" {}

data "forward_aws_organization_accounts" "current" {
  role_name   = "ForwardRole"
  external_id = data.forward_aws_assume_role_external_id.current.external_id
}

resource "forward_aws_cloud_account" "organization" {
  name    = "AWS-PROD"
  regions = ["us-east-1"]

  assume_role_infos = data.forward_aws_organization_accounts.current.assume_role_infos
}
```

## CLI Fallback Flow

1. Apply the AWS Organizations read role in the management account or delegated administrator account.
2. Apply the collection-role StackSet to the target OU/root so every member account gets the same role name.
3. Run `awssync discover-org` with the role name and collection regions.
4. Use `--post --yes` only when ready to create the new Forward AWS setup.

```bash
terraform -chdir=examples/terraform/aws-org-discovery-role init
terraform -chdir=examples/terraform/aws-org-discovery-role apply

terraform -chdir=examples/terraform/forward-collection-role-stackset init
terraform -chdir=examples/terraform/forward-collection-role-stackset apply

AWS_PROFILE=org-readonly ./bin/awssync discover-org \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --external-id Org:12345
```

## Security Notes

- Do not put static IAM access keys in Terraform state unless there is no alternative; if you do, use protected encrypted remote state.
- Prefer AWS IAM role/OIDC flows for `discover-org` automation.
- For Forward static-key collection, pass collector secrets to `awssync` through runtime secret storage, not Terraform outputs.
- The StackSet example defaults to AWS `ReadOnlyAccess`; replace that with a Forward-approved least-privilege policy when available.
