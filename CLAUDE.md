# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`awssync` is a Go CLI (cobra/viper, Go 1.26) that keeps the AWS account list of an existing Forward Networks cloud setup in sync with the AWS inventory Forward has already collected. The primary operator command is `safe-sync` (additive only: add/re-enable, never remove). Other commands: `run`/sync, `sync-accounts` (reviewed manifest, the only path that may remove accounts), `apply-plan`, `preflight`, `status`, `wait`, `discover-org`, `onboard-accounts`, `external-id`, `serve-webhook`, `configure-webhook`.

## Commands

```bash
make build        # -> bin/awssync (ldflags inject version/commit/buildDate into package main)
make test         # go test ./...
make race         # go test -race ./...
make fmt-check    # gofmt -l ./cmd ./internal (make fmt to fix)
make vet
make vuln         # govulncheck
make ci           # fmt-check vet test race vuln build — run before publishing
go test ./internal/app -run TestName    # single test
```

## Architecture

- `cmd/awssync/main.go` — all cobra commands, flag binding, human/JSON output emitters, and `safe-sync` orchestration (preview → `apply` prompt → digest-bound apply). Keep CLI-only logic here; safety guarantees should live in `internal/app`.
- `internal/api` — thin facade over `github.com/forwardnetworks/forward-go-sdk`. All Forward traffic goes through the SDK; do not add `net/http` calls to Forward. Missing capability → ask the SDK repo (`~/src/forward-go-sdk`, its own Claude session) rather than hand-rolling a request. `--api-prefix` is accepted only as `/api`.
- `internal/app` — the core. Every mode produces a typed desired state (`domain.go`, `adapters.go` for NQE/manifest/External-ID inputs, `reconcile.go`/`run.go` for diffing), then mutates Forward only via `GuardAndApply` in `apply_gateway.go`. That gateway owns authorization/digest check, removal/disable ceilings (`removal_limits.go`), zero-diff skip, rollback file, last-moment equality re-read, PATCH, and the per-setup result journal.
- `internal/awsorg` — AWS Organizations discovery. `internal/monitor` — status/wait. `internal/webhook` — authenticated receiver with a durable JSON state file (dedupe, snapshot watermarks, pending/dead-letter queue).

## Invariants to preserve

- Forward ignores `offset` on the snapshot listing and returns everything when `limit` is unset, so `ListSnapshots` is one unlimited call (a `limit` silently truncates). The SDK's `PATCH` is never auto-retried (only 429/503 are, for any method).
- PATCH uses `CloudAccounts.Patch` (presence semantics). Never use the SDK's `CloudAccounts.Update`/`CloudAccountRequest` for PATCH: its `collect` always serialises and would disable collection.

- **Single PATCH chokepoint:** `internal/app/patch_chokepoint_test.go` enforces exactly one production caller of `api.PatchCloudAccount`. Don't add another; route through `GuardAndApply`.
- **Absence never means deletion for NQE data.** The NQE source is `network.cloudAccounts` (observed/partial, not a configured-account inventory), so NQE policy is `Additive` only and `--prune-missing` is refused. Removal is only legitimate from a human-reviewed manifest (`sync-accounts`, `CompleteInventory`) with `--allow-removals`, ceilings, and (unattended) `--allow-unattended-destructive`.
- Account IDs are validated as exactly 12 digits; malformed rows fail the whole plan (deliberately fail-closed). Duplicate/conflicting identities are rejected.
- Forward PATCH semantics: top-level merge; `assumeRoleInfos` is replaced wholesale when present; no ETag/CAS exists, so the re-read check is best-effort, not atomic. Setup identity is by targeting name.
- Webhook apply mode requires Basic Auth and an explicit network; event scope may only narrow configured scope.
- Rollback files are pre-change PATCH payloads, not full setup backups.
- Per CONTRIBUTING: keep destructive behavior opt-in, preserve dry-run output, add regression tests for safety checks, and do not add tool/AI identities to commit or PR attribution (no `Co-authored-by` for tools).

## Live testing

`~/sewest.token` is two lines (user, password) for `https://fwd.app`; export as `FWD_HOST`/`FWD_USER`/`FWD_PASSWORD` and never print it. Network `244824` (one AWS setup) is a throwaway for write tests: apply, then restore with `apply-plan --plan <x>.rollback.json --yes` and compare `GET /api/networks/244824/cloudAccounts` byte-for-byte.

## Misc

- `docs/ARCHITECTURE_REVIEW.md` is the historical safety review and rationale; `docs/upgrading.md`, `routine-safe-sync.md`, `govcloud-workflow.md` cover operator workflows. Update docs when operator-visible behavior changes.
- Generated `aws_sync_payload_*.json` / `fwd_accounts_data_*.json` files accumulate under `cmd/awssync/` and `internal/app/` during runs/tests; they are gitignored and may contain tenant data — never commit them or copy them into fixtures (use `internal/app/testdata`).
