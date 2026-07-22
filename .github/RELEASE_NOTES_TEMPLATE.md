## aws-sync {{VERSION}}

### Highlights

- Generated payload, manual, and audit files are now atomically replaced with owner-only `0600` permissions, including outputs that may contain static AWS credentials.
- Forward API reads, NQE queries, and full-state PATCH operations retry bounded transient `429`, `502`, `503`, and `504` responses. Non-idempotent create POSTs remain single-attempt.
- `awssync --version` now reports the release, source commit, and build date.
- CI now runs formatting, vet, tests, the race detector, and `govulncheck` with read-only repository permissions and commit-pinned actions.
- Release jobs use least-privilege permissions and continue to publish checksums and build-provenance attestations.
- The README now starts with the workflow decision diagram and routes detailed operator procedures to focused runbooks.
- Contribution guidance requires human attribution and excludes automation/tool identities from contributor metadata.

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
