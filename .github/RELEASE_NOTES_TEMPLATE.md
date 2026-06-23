## aws-sync {{VERSION}}

### Highlights

- Positioned the Forward Terraform provider as the native IaC workflow for new AWS Organizations onboarding.
- Kept `awssync` focused on existing Forward setup synchronization from NQE data plus manual/break-glass onboarding artifacts.
- Added `discover-org` for initial AWS Organizations onboarding before Forward has collected the org.
- Writes both onboarding artifacts:
  - `fwd_accounts_data_<timestamp>.json` for Forward UI drag-and-drop import.
  - `aws_create_payload_<timestamp>.json` for `POST /api/networks/{networkId}/cloudAccounts`.
- Added AWS Organizations access checks using `DescribeOrganization`, `ListAccounts`, and `ListParents`.
- Added optional `discover-org --post --yes` to create a new Forward AWS setup from automation.
- Kept onboarding separate from existing setup sync: `discover-org` does not PATCH existing setups.
- Added static-key onboarding support with explicit collector credential flags and placeholder protection when the secret is not supplied.
- Updated docs and Mermaid architecture diagrams for NQE sync, direct Organizations onboarding, and webhook operation.

### Download and verify

Assets include platform binaries, tarballs, checksums, and release attestations:

- `awssync-linux-amd64`
- `awssync-linux-arm64`
- `awssync-darwin-amd64`
- `awssync-darwin-arm64`
- `awssync-linux-amd64.tar.gz`
- `awssync-linux-arm64.tar.gz`
- `awssync-darwin-amd64.tar.gz`
- `awssync-darwin-arm64.tar.gz`
- `sha256sums.txt`

### Quick usage

```bash
# Dry run + payload review
./awssync --network-id <NETWORK_ID> --output aws_sync_payload.json --manual-output aws_sync_manual_payload.json

# Apply safely in automation
./awssync --network-id <NETWORK_ID> --apply --yes --output aws_sync_payload.json

# Apply an exact reviewed payload file
./awssync apply-plan --plan aws_sync_payload.json --yes

# Discover a not-yet-onboarded AWS Organization
AWS_PROFILE=org-readonly ./awssync discover-org \
  --setup-id AWS-PROD \
  --role-name ForwardRole \
  --collect-region us-east-1 \
  --external-id Org:12345
```
