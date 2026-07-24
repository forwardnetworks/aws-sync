## aws-sync {{VERSION}}

### Highlights

- NQE reconciliation is additive by default: configured accounts missing from the current NQE result remain in the setup, while discovered disabled accounts are re-enabled.
- NQE-based deletion now requires `--prune-missing`, `--allow-removals`, and both nonzero `--max-removals` and `--max-removal-percent` bounds.
- Every apply writes a complete pre-change `.rollback.json` payload and verifies that the selected setup state has not changed before the first PATCH.
- CLI runs pin the latest processed snapshot so planning and apply use one immutable NQE inventory.
- Invalid NQE account-ID placeholders are ignored and reported instead of becoming AWS accounts.
- Human-readable output is now the default; use `--json` or `--format json` for automation.
- Regression coverage includes the reported 325-account setup with only 10 enabled, additive and explicit-prune paths, concurrent setup changes, rollback, and snapshot pinning.
- Per-account External ID selection and CSV workflows from v2.3.0 remain supported.
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
  --output aws_sync_payload.json
```

Routine automation should omit all removal flags. See the README workflow diagram, `docs/aws-account-sync-procedure.md`, and `docs/govcloud-workflow.md` before enabling account removals.
