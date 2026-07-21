## aws-sync {{VERSION}}

### Highlights

- Added `--max-removals` and `--max-removal-percent` blast-radius ceilings across NQE sync, manifest sync, saved-plan apply, preflight, and webhook workflows.
- Added release installation, checksum, provenance verification, automation audit handling, and explicit External ID rollback guidance.
- Fixed the release checksum manifest so downloaded assets verify directly with `sha256sum -c sha256sums.txt`.
- Added reversible one-time External ID migration for existing AWS setups with `external-id --value` and `external-id --clear`.
- Added AWS GovCloud workflows for both regular Forward Organizations/NQE discovery and reviewed standalone-account manifests.
- Added `onboard-accounts` and `sync-accounts` for environments where AWS Organizations is unavailable by policy.
- Preserved `arn:aws-us-gov` IAM role partitions and rejected mixed or region-mismatched role ARNs.
- Blocked GovCloud removals without positive Organizations evidence; authoritative manifest removals require explicit review and `--allow-removals`.
- Added collector instance-profile onboarding payloads for self-managed GovCloud collectors.
- Hardened `apply-plan` so saved payloads cannot bypass current-state or GovCloud removal validation.
- Added a dedicated GovCloud operator guide with product-enhancement escalation criteria.

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
# Add a customer-defined External ID to an existing setup
./awssync external-id \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID> \
  --value <CUSTOMER_VALUE> \
  --output aws_external_id_payload.json

# Generate a GovCloud onboarding payload from a reviewed manifest
./awssync onboard-accounts \
  --accounts-file govcloud-accounts.json \
  --partition aws-us-gov \
  --credential-mode instance-profile \
  --setup-id <SETUP_ID> \
  --role-name ForwardReadOnlyAccess \
  --collect-region us-gov-west-1

# Dry-run an existing setup against an authoritative manifest
./awssync sync-accounts \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID> \
  --accounts-file govcloud-accounts.json \
  --format human

# Verify the regular Organizations/NQE path before applying
./awssync preflight \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID> \
  --max-snapshot-age 24h \
  --format human
```

See `docs/govcloud-workflow.md` for the complete GovCloud Organizations and standalone-account procedures.
