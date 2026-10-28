## aws-sync {{VERSION}}

{{THIS_RELEASE}}

### Upgrading from v2.x

v3.0.0 removed NQE-based account removal and made webhook authentication and
unattended destructive authorization mandatory. If you are coming from v2.x,
read [docs/upgrading.md](https://github.com/forwardnetworks/aws-sync/blob/main/docs/upgrading.md)
before installing — three previously-working invocations now fail closed.

### Known limitation

Forward's cloud-account API provides no ETag, version field, or other
compare-and-swap token.

Post-apply verification detects unexplained divergence after a write. It cannot
detect a concurrent edit that arrived between this tool's final read and its
PATCH: the full-list write erases it, and the resulting state then matches the
approved intent exactly, leaving nothing observable.

Combined with the pre-PATCH comparison, what remains uncovered is an edit
landing inside the PATCH execution window. Prefer `safe-sync` for routine work,
and avoid unattended destructive runs on setups that people also edit by hand.

### Download and verify

Assets include native Linux and macOS binaries for amd64 and arm64, tar archives, `sha256sums.txt`, an SBOM (`sbom.spdx.json`), and GitHub build-provenance attestations. See [docs/security-review.md](https://github.com/forwardnetworks/aws-sync/blob/main/docs/security-review.md) for what the tool does.

```bash
tar -xzf awssync-linux-amd64.tar.gz
sha256sum -c sha256sums.txt --ignore-missing
gh attestation verify awssync-linux-amd64 \
  --repo forwardnetworks/aws-sync
./awssync-linux-amd64 --version
```

### Start safely

```bash
./awssync-linux-amd64 safe-sync \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID>
```

Routine automation should use the standard command and omit all removal flags. See the README workflow diagram, `docs/routine-safe-sync.md`, `docs/aws-account-sync-procedure.md`, and `docs/govcloud-workflow.md` before enabling account removals.
