## aws-sync {{VERSION}}

### Highlights

- Added `--manual-output` to generate setup-keyed manual drag-and-drop payloads for Forward UI workflows.
- Exposed manual payload metadata in JSON summary:
  - `manual_output`
  - `manual_payload_sha256`
  - `manual_payloads`
- Improved multi-setup AWS Organization safety checks for removals.

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
- `awssync-checksums.txt`

### Quick usage

```bash
# Dry run + payload review
./awssync --network-id <NETWORK_ID> --output aws_sync_payload.json --manual-output aws_sync_manual_payload.json

# Apply safely in automation
./awssync --network-id <NETWORK_ID> --apply --yes --output aws_sync_payload.json

# Apply an exact reviewed payload file
./awssync apply-plan --plan aws_sync_payload.json --yes
```
