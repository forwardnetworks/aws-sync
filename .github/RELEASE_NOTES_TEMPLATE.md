## aws-sync {{VERSION}}

### Highlights

- `awssync external-id` can now target one or more `--account-id` values while preserving every unselected account.
- A reviewed `--external-id-file` CSV supports different values and explicit set/clear actions per setup and account.
- Normal NQE, webhook, and authoritative-manifest syncs preserve mixed per-account External IDs instead of flattening them to the first configured value.
- New accounts in a mixed-ID setup fail closed unless the plan receives an explicit per-account CSV assignment.
- CSV validation rejects malformed IDs, duplicates, implicit clears, wrong setups, and accounts outside the planned inventory before PATCH.
- Dry-run summaries report selected, changed, unchanged, set, and cleared account counts plus per-account change metadata.
- Release assets remain available for Linux and macOS on amd64 and arm64 with SHA-256 checksums and GitHub build-provenance attestations.

### Download and verify

Assets include native Linux and macOS binaries for amd64 and arm64, tar archives, `sha256sums.txt`, and GitHub build-provenance attestations.

```bash
tar -xzf awssync-linux-amd64.tar.gz
sha256sum -c sha256sums.txt --ignore-missing
gh attestation verify awssync-linux-amd64 \
  --repo forwardnetworks/aws-sync
./awssync-linux-amd64 --version
```

### Start safely

```bash
./awssync-linux-amd64 preflight \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID> \
  --max-snapshot-age 24h \
  --format human

./awssync-linux-amd64 \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID> \
  --max-snapshot-age 24h \
  --output aws_sync_payload.json \
  --format human
```

See the README workflow diagram, `docs/aws-account-sync-procedure.md`, and `docs/govcloud-workflow.md` before enabling apply automation or account removals.
