## aws-sync {{VERSION}}

### Breaking changes

Read this section before upgrading. These changes fail closed, so an automated
deployment that does not act on them will stop working rather than degrade.

**1. NQE-based account removal has been removed.**

`--prune-missing` remains a recognized option so existing automation receives
an actionable error, but it always refuses before credentials, NQE, planning,
or PATCH work. NQE is observed snapshot inventory, not an authoritative account
manifest, so an absent row cannot prove an account should be deleted. Replace
NQE prune workflows with `sync-accounts` and a complete human-reviewed manifest.
Manifest removals still require `--allow-removals` and both nonzero removal
ceilings.

**2. `serve-webhook --apply` now requires authentication and an explicit network.**

The server previously accepted unauthenticated requests when no webhook
credentials were configured, and let an event select any network or setup. It
now refuses to start in apply mode without all three of:

```bash
awssync serve-webhook --apply --yes \
  --webhook-basic-username <USER> \
  --webhook-basic-password <PASSWORD> \
  --network-id <NETWORK_ID>
```

Configure Forward to send matching credentials (`awssync configure-webhook`).
Event scope is now intersected with configured scope: an event naming a
different network, or a setup outside `--setup-id`, is rejected with `403`
instead of being honored.

The server also persists dedupe and snapshot-ordering state to
`$UserConfigDir/awssync/webhook-state.json`. Ensure the service user can write
that directory, or set `--webhook-state-file`.

**3. Destructive applies in unattended contexts now require an explicit flag.**

Forward's API exposes no compare-and-swap token, so a concurrent edit in the UI
cannot be detected before a full-list PATCH overwrites it. Removals and disables
requested without a human present now require `--allow-unattended-destructive`:

```bash
awssync sync-accounts --apply --yes --allow-unattended-destructive ...
awssync apply-plan --allow-unattended-destructive ...   # when removing/disabling
awssync serve-webhook --apply --yes --allow-unattended-destructive ...
```

`--yes` counts as unattended even in a terminal. The flag does not bypass
`--allow-removals`, evidence rules, or either removal ceiling — it is an
additional acknowledgement, not a replacement. `safe-sync` is unaffected,
being additive-only. Non-destructive applies are unaffected.

### Safety changes

- NQE reconciliation is unconditionally additive. Pagination completeness checks remain to diagnose truncated observed data, but completeness no longer authorizes absence-based deletion.
- A malformed account ID now fails the plan instead of being silently skipped, since skipping rows is how a partial inventory becomes a deletion. Use `--allow-malformed-rows` to skip and report them; doing so marks the inventory incomplete and therefore blocks removals.
- Setting an account to `enabled: false` is now classified as destructive. It consumes the same authorization and removal ceilings as deletion, closing a path where `apply-plan` could disable every account in a setup without tripping any removal guard.
- All account-list writes go through one guarded apply path, enforced by a test that fails if any other caller appears.
- External ID rotation now writes a pre-change rollback artifact, re-reads before PATCH, and binds confirmation to the computed payload.
- A partial multi-setup apply reports per-setup disposition (applied, pending, conflicted, failed) and a result-journal path instead of a bare error.
- Planning is deterministic: preview and apply produce identical digests for identical inputs.
- Cross-setup account moves are refused. Sequential per-setup PATCHes cannot guarantee an account ends up in exactly one setup if the run fails midway.

### Known limitation

Forward's cloud-account API provides no ETag, version field, or other
compare-and-swap token. A concurrent edit made in the Forward UI between this
tool's final read and its PATCH will be overwritten, and this is deterministic
rather than a narrow race. The pre-PATCH re-read narrows the window but does not
close it. Prefer `safe-sync` for routine work, and avoid unattended destructive
runs on setups that people also edit by hand.

### Highlights

- New `awssync safe-sync` command provides a one-command routine workflow: 24-hour snapshot freshness, preflight, compact preview, additive-only enforcement, one confirmation, rollback, and apply.
- `safe-sync` does not expose prune or removal controls and stops before PATCH if preflight is not ready or the reviewed payload changes.
- A zero-change `safe-sync` exits successfully without PATCHing Forward or refreshing setup test timestamps.
- The README is now novice-first, with the routine workflow, count definitions, expected output, common stop conditions, and a short decision diagram before expert features.
- A one-page routine operator handoff is available at `docs/routine-safe-sync.md`.
- NQE reconciliation is additive by default: configured accounts missing from the current NQE result remain in the setup, while discovered disabled accounts are re-enabled.
- NQE-based deletion is retired; `--prune-missing` returns an actionable refusal and reviewed manifest removal remains available through `sync-accounts`.
- Every apply writes a complete pre-change `.rollback.json` payload and verifies that the selected setup state has not changed before the first PATCH.
- CLI runs pin the latest processed snapshot so planning and apply use one immutable NQE inventory.
- Invalid NQE account-ID placeholders are ignored and reported instead of becoming AWS accounts.
- Human-readable output is now the default; use `--json` or `--format json` for automation.
- Regression coverage includes 0, 1, 10, half, and all-enabled account states; additive NQE and authoritative-manifest paths; multi-setup isolation; concurrent setup changes; rollback; and snapshot pinning.
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
./awssync-linux-amd64 safe-sync \
  --network-id <NETWORK_ID> \
  --setup-id <SETUP_ID>
```

Routine automation should use the standard command and omit all removal flags. See the README workflow diagram, `docs/routine-safe-sync.md`, `docs/aws-account-sync-procedure.md`, and `docs/govcloud-workflow.md` before enabling account removals.
