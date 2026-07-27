## aws-sync {{VERSION}}

### This release

Additive safety hardening. **No breaking changes** — upgrading from v3.0.0
requires no configuration changes.

- **Post-apply verification.** Each setup is re-read after a successful PATCH
  and compared against the approved target. Unexplained divergence stops the
  apply, is recorded as `conflicted` in the result journal, and points at the
  rollback artifact. No automatic remediation is attempted: a corrective PATCH
  would repeat the same overwrite, and deciding whose change wins is a human
  call.

  This narrows the concurrent-edit gap; it does not close it. See *Known
  limitation* below for exactly what remains undetectable.

- **Manifest quality warnings.** `sync-accounts` warns when a manifest closely
  matches observed NQE inventory while diverging from configured membership —
  the signature of a manifest derived from NQE, which reproduces by hand the
  unsound inference retired in v3.0.0. It warns rather than blocks.

- **Removal impact is always stated.** Previews now say "removes 968 of 978
  accounts (98.98%)" regardless of what the configured ceilings permit.

- **Webhook state locking.** A second daemon sharing a state file now fails
  fast instead of silently corrupting dedupe records and snapshot watermarks.

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
./awssync-linux-amd64 safe-sync \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID>
```

Routine automation should use the standard command and omit all removal flags. See the README workflow diagram, `docs/routine-safe-sync.md`, `docs/aws-account-sync-procedure.md`, and `docs/govcloud-workflow.md` before enabling account removals.
