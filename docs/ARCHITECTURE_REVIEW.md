# Architecture Review: `awssync`

Review date: 2026-07-25  
Repository state reviewed: `0c0dbd5` (`forwardnetworks/aws-sync`)

## Executive summary

- **CRITICAL — CONFIRMED — FIXED (`1828278`, `e854787`):** the original review found independent existing-setup mutation paths. Existing AWS setup PATCHes now have one typed intent model and one test-enforced `GuardAndApply` chokepoint. Setup creation remains a separate POST operation because it does not replace an existing account list (`internal/app/apply_gateway.go`, `internal/app/patch_chokepoint_test.go`).
- **CRITICAL — CONFIRMED — FIXED (current uncommitted retirement):** NQE pruning equated “not present in this observed query result” with “remove from the setup.” The deeper error was treating `network.cloudAccounts` as a configured-account inventory at all: it is a union of successfully collected accounts and accounts merely visible through Organizations metadata, with routine partial results. `--prune-missing` now refuses and the NQE policy constructor can produce only `Additive`; planning also rejects `CompleteInventory` for an NQE source.
- **CRITICAL — CONFIRMED — FIXED (current uncommitted retirement):** A partial NQE result could remove most configured accounts when pruning and sufficiently broad ceilings were enabled. Live measurements on 2026-07-25 showed network `253234` at 978 configured versus 10 NQE rows (968 deletions, all enabled), and network `253236` at 565 configured versus 540 rows (27 deletions, all enabled). The removal path is now unreachable regardless of pagination completeness or evidence flags.
- **CRITICAL — CONFIRMED:** A truly empty NQE result is rejected, so zero rows do not directly become “delete everything”; this protection does not cover a one-row or otherwise partial result (`internal/app/run.go:1084-1102`).
- **CRITICAL — CONFIRMED:** The client reads a setup, constructs a complete `assumeRoleInfos` array, and PATCHes it without `ETag`, version, `If-Match`, or another atomic compare-and-swap token (`internal/api/client.go:76-105`, `internal/api/client.go:344-363`, `internal/api/client.go:432-440`).
- **CRITICAL — CONFIRMED:** The pre-PATCH re-read is only a time-of-check check; a Forward UI edit after that GET and before the PATCH can still be overwritten (`internal/app/run.go:337-356`, `internal/app/run.go:1851-1870`).
- **HIGH — CONFIRMED:** `apply-plan` classifies danger only by missing account IDs; a reviewed payload can keep every ID but set every account to `enabled:false` without `--allow-removals` or removal ceilings (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-130`).
- **HIGH — CONFIRMED — FIXED (`e854787`):** External ID remains a specialized planning adapter, but mutation now uses the shared intent/gateway with rollback, final equality re-read, digest authorization, zero-diff suppression, and result journal. Atomic revision checking remains unavailable (`internal/app/external_id.go`, `internal/app/apply_gateway.go`).
- **HIGH — CONFIRMED:** Standard interactive sync previews and confirms one computation, then recomputes without passing the reviewed payload hash; only `safe-sync` binds apply to the preview digest (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:213-240`).
- **HIGH — CONFIRMED:** Webhook jobs call `app.Run` directly, so they bypass the preflight command and any per-job confirmation; startup `--yes` is the only confirmation (`cmd/awssync/main.go:847-887`, `internal/webhook/server.go:167-193`).
- **HIGH — CONFIRMED — FIXED (current uncommitted webhook slice):** webhook apply mode requires Basic Auth, and event network/setup scope can only equal or narrow configured scope (`internal/webhook/server.go`).
- **HIGH — CONFIRMED:** Webhook deduplication records an event before queue admission and before successful processing; queue-full and failed-job retries can be acknowledged as duplicates and lost (`internal/webhook/server.go:139-148`, `internal/webhook/server.go:180-215`).
- **HIGH — HISTORICAL, NQE DESTRUCTIVE CONSEQUENCE FIXED:** Older delayed webhook events were especially dangerous when the daemon could prune. Webhook NQE work is now additive even if event ordering regresses; ordering still matters for correctness of additions/re-enables.
- **HIGH — CONFIRMED:** Multi-setup apply is a sequential PATCH loop with no transaction or durable progress record; failure on setup N leaves earlier setups changed and later setups untouched (`internal/app/run.go:851-863`, `internal/app/run.go:356-359`).
- **HIGH — CONFIRMED:** HTTP PATCH is automatically retried after transport and selected status failures, but no idempotency key or revision precondition is sent (`internal/api/client.go:402-450`, `internal/api/client.go:460-492`).
- **HIGH — CONFIRMED:** `safe-sync` is genuinely additive with respect to membership and refuses its own preview if it contains removals, but those guarantees live in its CLI orchestration rather than the mutation boundary (`cmd/awssync/main.go:165-240`, `internal/app/run.go:1063-1076`).
- **HIGH — CONFIRMED:** `sync-accounts` treats a reviewed manifest as authoritative and turns omission into removal; it bypasses NQE candidate and organization-evidence checks by setting `AuthoritativeInput` (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:321-333`).
- **HIGH — CONFIRMED:** There is no domain distinction between “absent,” “suspended,” “closed,” “moved,” and “explicitly deprovisioned” in the reconciliation rows; the planner consumes raw string-keyed maps containing only ID/name/setup/evidence fields (`internal/app/run.go:20-39`, `internal/app/run.go:1263-1311`).
- **MEDIUM — CONFIRMED:** The NQE paginator stops on any short page and has no total-count, completeness marker, repeated-page detection, or maximum-page guard (`internal/api/client.go:227-277`).
- **MEDIUM — CONFIRMED:** In single-setup mode, local filtering is disabled and rows without setup identity are assigned to that setup, increasing the damage from a saved query or server-side filter that returns overbroad data (`internal/api/client.go:302-318`, `internal/app/run.go:1326-1347`).
- **MEDIUM — CONFIRMED — FIXED (`00b7e89`):** the original adapters silently accepted some first-wins duplicates. Typed adapters now reject duplicate/conflicting account identities consistently (`internal/app/adapters.go`, `internal/app/domain.go`).
- **MEDIUM — CHANGED (Phase 1):** The shared domain now validates exactly 12 digits in NQE parsing as the account-ID contract; this fails previously lenient inputs consistently and is a deliberate fail-closed availability tradeoff (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/external_id.go:142-153`).
- **MEDIUM — CONFIRMED:** Additive reconciliation re-enables every disabled account retained in the target, including configured accounts absent from the NQE result (`internal/app/run.go:1228-1261`, `internal/app/run.go:1666-1672`).
- **MEDIUM — CONFIRMED — FIXED (current uncommitted webhook slice):** explicit snapshot IDs, including webhook-supplied snapshots, are looked up and checked against `MaxSnapshotAge`; webhook watermarks also reject old-after-new delivery (`internal/app/run.go`, `internal/webhook/state.go`).
- **MEDIUM — CONFIRMED:** Generated payloads can be time-dependent because a zero region `TestInstant` is replaced with `time.Now()`, making preview/apply digest stability depend on current setup data (`internal/app/run.go:1765-1781`).
- **MEDIUM — CONFIRMED:** `status` performs non-atomic “latest” and “list” reads, while `wait` has no monotonicity, paginated snapshot listing, unknown-terminal-state, or missing-snapshot handling beyond polling until context cancellation (`internal/api/client.go:334-342`, `internal/monitor/monitor.go:25-51`, `internal/monitor/monitor.go:54-100`).
- **MEDIUM — CONFIRMED:** The test suite contains meaningful removal, GovCloud, bounds, hash, and pre-PATCH-change tests; it is not merely happy-path coverage (`internal/app/run_test.go:389-433`, `internal/app/run_test.go:826-863`, `internal/app/run_test.go:931-1302`, `internal/app/apply_plan_test.go:72-251`).
- **HIGH — CONFIRMED:** The highest-risk adversarial cases remain untested: an edit in the final GET/PATCH race window, partial multi-setup apply, incomplete nonempty inventory, disabling through `apply-plan`, webhook retry loss/order, and External ID concurrency (`internal/app/apply_plan_test.go:209-251`, `internal/webhook/server_test.go:18-185`, `internal/app/external_id_test.go:16-229`).
- **MEDIUM — CONFIRMED:** Documentation says every apply writes rollback data, but External ID apply writes only an audit payload and the procedure documents manual reversal instead (`README.md:178-188`, `internal/app/external_id.go:241-251`, `docs/aws-account-sync-procedure.md:438-458`).
- **HIGH — CONFIRMED — HISTORICAL, FIXED (`1828278`, `e854787`):** the original review found safety spread across individual seams. Phase 3 replaced the divergent mutation sites with one guarded engine; the historical finding is retained to explain the refactor.
- **TARGET:** All modes should produce one typed `DesiredSetup`, one typed field-level `ChangeSet`, and one immutable `ApplyIntent`; every PATCH must pass one guard/CAS/audit gateway (`internal/app/run.go:955-980`, `internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:62-251`).
- **TARGET:** Absence must not mean deletion unless the source proves completeness and organization/setup identity, or supplies an explicit deprovision tombstone (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
- **TARGET STATUS:** authorization, removal/disable ceilings, zero-diff skip, rollback/audit, last-moment conflict detection, PATCH, and result journaling now live in `GuardAndApply`. Atomic concurrency and idempotent retry remain blocked by the Forward API contract (`internal/app/apply_gateway.go`).

## Corrections (2026-07-25)

- **2026-07-25:** The review's central NQE assumption is corrected. `FQ_6d355dca…` queries the snapshot's observed `network.cloudAccounts`, not configured Forward account membership and not an authoritative AWS Organizations inventory. Forward constructs that data as the union of accounts that collected successfully and accounts visible through `organizations:ListAccounts` metadata (`CloudAccountUtils.java:46,73`). Collector authorization failures are ignored (`AwsApi.java:1489`), and service exceptions return the partial accumulated list (`AwsPipeline.java:2681`). Pagination completeness can prove only that this already-partial result terminated cleanly; it cannot make absence a deletion signal.
- **2026-07-25:** Live production measurements demonstrate the consequence: network `253234` had 978 configured accounts and 10 NQE rows, so pruning would delete 968 accounts, all 968 enabled; network `253236` had 565 configured accounts and 540 NQE rows, so pruning would delete 27 accounts, all 27 enabled.
- **2026-07-25:** NQE-based removal is retired. The CLI keeps `--prune-missing` recognized but refuses it with guidance to `sync-accounts`; NQE policy construction is additive-only and planning rejects `CompleteInventory` for NQE snapshots. `CompleteInventory` remains because a complete human-reviewed manifest is legitimately authoritative, and `sync-accounts` continues through `ComputeDesired` and `GuardAndApply`.
- **2026-07-25:** `SUSPECTED` finding at the Forward boundary on unmodeled field loss is corrected to `CONFIRMED` top-level merge semantics with preserved omissions, based on `UpdateCloudAccountRequest.applyTo` in `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java`.
- **2026-07-25:** `SUSPECTED` behavior for `assumeRoleInfos` merge-vs-replace was updated to **CONFIRMED** replace-when-present; the field is set from the parsed request array in `UpdateAwsAccountRequest.applyTo` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateAwsAccountRequest.java:88-91`).
- **2026-07-25:** Concurrency findings were corrected: no client-visible ETag/version or `If-Match` contract exists on `PatchCloudAccount`, and Forward’s internal update path uses a `kvStore.getAndUpdate` retry loop that can deterministically reapply stale intent onto fresh state (`~/src/fwd/app/src/main/java/com/forwardnetworks/cv/sources/cloud/CloudAccountService.java:204-235`). Phase 4 is therefore not blocked by ambiguity; it is closed pending API contract change and policy controls.
- **2026-07-25:** Additional confirmed server-side behavior now recorded: duplicate `assumeRoleInfos` account IDs are rejected with `BadRequestException`, and single-account setups cannot be updated to multi-account.
- **2026-07-25:** Operational facts were added: network `253234` has `978` accounts against `PageLimit = 1000` (22 accounts of headroom before truncation becomes immediate), and setup identity is targeting-name based on both `run` and API route binding (`internal/api/client.go:19`, `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/controller/CloudAccountController.java:196-204`).
- **2026-07-25:** Confirmed that `regionToProxyServerId` is currently preserved by omission and explicitly copied from current setup state before patch payload construction (`internal/app/run.go:1837`), matching observed behavior despite `collect`-field omissions.
- **2026-07-25:** Phase 1 deliberately made account-ID parsing fail-closed, and the tradeoff is recorded as explicit risk: one malformed NQE row now fails the whole plan instead of being silently skipped. Skipping rows is the mechanism by which a partial inventory becomes a deletion, so failing closed is the intended behavior — but on a large setup a single bad row is a full sync outage.
- **2026-07-25:** Phases 1 and 2 are complete. Commit `00b7e89` introduced typed domain adapters, `8cf4ef9` made absence-based removal fail closed without completeness proof, and `fbf78bb` centralized deterministic desired-state/diff computation. Findings below are retained and marked fixed rather than removed.
- **2026-07-25:** Phase 3 is complete. Commits `1828278` and `e854787` route planned sync, manifests, `apply-plan`, and External ID mutation through `GuardAndApply`. `internal/app/patch_chokepoint_test.go` enforces exactly one production caller of `api.PatchCloudAccount`.
- **2026-07-25:** The Phase 4 CAS proposal is closed by finding, not implemented: Forward exposes no revision token. Commit `1828278` shipped the compensating `--allow-unattended-destructive` policy, the last-moment equality re-read, and a durable per-setup result journal; neither is atomic CAS.
- **2026-07-25:** The current uncommitted webhook slice (left uncommitted by instruction) requires Basic Auth and an explicit configured network whenever apply is enabled, intersects event and configured scope, records successful scoped dedupe and snapshot watermarks in an atomic JSON state file, makes failed work redeliverable, rejects backward snapshot movement, and validates explicit snapshot age. Phase 0's guarded webhook characterization assertions pass unchanged when enabled; only per-test state-file isolation/cleanup scaffolding was added.
- **2026-07-25:** Phase 5 webhook durability is complete in the current uncommitted slice. Schema v2 adds pending and dead-letter event records to the existing atomic state file, persists admission before `202`, replays queued and in-flight work after restart, and bounds failures at five attempts with exponential backoff. Re-delivering a dead-lettered event starts a fresh bounded cycle so an operator can drain it after correcting the cause. Dedupe and watermarks are still written only in the atomic success transition.
- **2026-07-25:** Rollback artifacts are corrected from “complete setup” copies to pre-change PATCH payloads. They contain the complete `assumeRoleInfos` account list and the PATCHable setup fields `type`, `name`, `regions`, `regionToProxyServerId`, and `proxyServerId`. They do not capture `collect`, `connectionTimeoutSeconds`, `requestTimeoutSeconds`, `numVirtualizedDevices`, or `useForwardAccountToAssumeRole`. This is safe for restoring an `awssync` mutation because Forward's top-level PATCH merge leaves absent fields unchanged, but the artifact is not a full backup and cannot reconstruct a setup from scratch.
- **2026-07-25:** Live write validation at `a674b3f` ran against Forward workspace networks `253234` and `253236`; both were restored to their byte-identical baseline endpoint hashes. Verified against real Forward were: `sync-accounts` removal of one account and restoration; the removal-ceiling, missing-`--allow-removals`, and missing-`--allow-unattended-destructive` refusals, each with a `failed` journal entry and no PATCH; `apply-plan` mutation and restoration from its emitted rollback for one setup and two setups; approval-digest stability across separate processes; webhook authentication, scope rejection with `403`, and dedupe suppression of a replay; `status` reporting `observation_atomic=false`; `wait`; and zero-diff suppression with no PATCH.
- **2026-07-25:** Two areas remain untested live. The older-snapshot `409` watermark rejection is unit-tested only because each validation workspace had a single snapshot. GovCloud paths are also test-only for this validation because neither workspace had an AWS GovCloud partition setup.
- **2026-07-25:** Live restoration also exposed an ordering distinction. Restoring an account set through `sync-accounts` sorts the list, so the raw endpoint hash can differ from the original even when the account configuration is semantically identical. Applying the emitted rollback preserves the original list order and reproduced the original endpoint bytes on both workspace networks. This is expected and matters only when operators use raw hashes to verify recovery.

## Review basis

This review covered the requested production files, their corresponding tests, the four named documents plus `README.md`, and the diffs for `0c0dbd5`, `2794e14`, `ac15c6c`, `fe4baf4`, and `b159af6`. The unmodified tree passed `go test ./...` and `go test -race ./...` (121 tests in six packages).

Severity is ranked as requested: **CRITICAL** means credible data loss or silent destructive overwrite; **HIGH** means a destructive bypass or serious correctness/operability failure; **MEDIUM** means a material modeling or resilience gap; **LOW** means localized maintainability or diagnostic debt.

“CONFIRMED” means the behavior is directly implemented or asserted in this repository. “SUSPECTED” means the conclusion depends on Forward server behavior or an external operational assumption not present in this repository.

---

## 1. Core model

### Verdict

#### CRITICAL — CONFIRMED: there is no single reconcile-and-apply model

The shared core is now typed adapters → pure reconciliation/classification → immutable `ApplyIntent` → `GuardAndApply`. Legacy CLI booleans are mapped once into tagged reconciliation policy at the boundary; they do not create alternate mutation paths (`internal/app/domain.go`, `internal/app/reconcile.go`, `internal/app/apply_gateway.go`).

`ApplyPlan` and `ChangeExternalID` independently reimplement setup lookup, current-state parsing, validation, audit, concurrency checking, and PATCH behavior (`internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:67-251`). Direct AWS Organizations and manifest onboarding use a separate create-payload builder and POST path, and deliberately refuse to update an existing named setup (`internal/app/run.go:376-542`).

### Every binary path that can mutate a Forward AWS setup

| Path | Desired-state computation | Mutation | Semantics and agreement |
|---|---|---|---|
| Root `awssync --apply` | Typed NQE adapter and pure additive reconcile; `--prune-missing` is recognized only to refuse | Sequential per-setup execution through `GuardAndApply` | NQE absence cannot remove membership; shares typed diff, digest authorization, rollback/re-read/PATCH/journal with every writer. |
| `safe-sync` | Preflight, dry-run `app.Run`, then a second `app.Run`; no prune flag is exposed | Shared `GuardAndApply` gateway | Additive membership and preview removal rejection are adapter guarantees; digest authorization and zero-diff suppression are shared gateway guarantees. |
| `webhook --apply --yes` | Authenticated event selects an exact snapshot and narrows configured network/setup scope, then calls ordinary `app.Run` (`internal/webhook/server.go`) | Shared `GuardAndApply` gateway | No preflight or per-event interactive confirmation; launch-time automation policy and intent digest apply, with durable event dedupe/watermark state. |
| `sync-accounts` | Reviewed manifest enters through the typed manifest adapter with complete-inventory policy | Shared `GuardAndApply` gateway | Omission is removal; the human manifest is the asserted completeness proof rather than NQE candidate/org evidence. |
| `apply-plan --yes` | Accepts operator-authored JSON targets, adapts them to typed payloads, and classifies every field change against current state | Shared `GuardAndApply` gateway | Lacks NQE candidate/completeness evidence by format, but disable/removal classification, budgets, digest, rollback, re-read, PATCH, and journal are shared. |
| `external-id --apply` | Typed explicit operations modify selected External IDs against current state | Shared `GuardAndApply` gateway | Preserves membership/enabled values and shares digest authorization, rollback, final re-read, zero-diff suppression, PATCH, and journal. AWS trust-policy readiness is not verified. |
| `discover-org --post` | Direct AWS Organizations discovery produces a create payload (`internal/awsorg/discover.go:75-107`, `internal/app/run.go:376-487`) | POST creates a new setup (`internal/app/run.go:476-487`) | It cannot reconcile an existing setup: an existing name is rejected, and zero discovered accounts are rejected (`internal/app/run.go:413-435`). |
| `onboard-accounts --post` | Reviewed manifest goes through the new-setup builder (`internal/app/account_manifest.go:62-68`, `internal/app/run.go:376-542`) | POST creates a new setup (`internal/app/run.go:476-487`) | It shares direct-onboarding semantics, not existing-setup reconciliation; the manifest loader requires a nonempty, unique, exact-12-digit list (`internal/app/account_manifest.go:21-59`). |

`configure-webhook` mutates Forward webhook configuration, not the AWS setup account list, while `status`, `wait`, and the monitor are read-only with respect to cloud setups (`cmd/awssync/main.go:907-1052`, `internal/monitor/monitor.go:25-100`).

### Semantic disagreements

- **HIGH — CONFIRMED:** The shared planner always emits `Enabled: true` for target accounts, so standard, safe, webhook, and manifest sync re-enable disabled entries; External ID rotation preserves their prior enabled flags, while `apply-plan` accepts either value (`internal/app/run.go:1244-1261`, `internal/app/run.go:1666-1672`, `internal/app/external_id.go:121-193`, `internal/app/apply_plan.go:58-79`).
- **HIGH — CONFIRMED — FIXED (current uncommitted retirement):** “Missing” formerly meant preserve in default NQE mode but remove in prune and manifest modes. NQE policy construction is now unconditionally `Additive`; only reviewed manifests construct `CompleteInventory`, and the planner rejects that policy when the snapshot source is NQE.
- **HIGH — CONFIRMED:** `apply-plan` recognizes only add/remove ID membership, while the main planner separately recognizes add/remove/re-enable and External ID state; neither has a general typed field-level diff (`internal/app/apply_plan.go:108-130`, `internal/app/run.go:1135-1158`).
- **MEDIUM — CONFIRMED:** Zero-change suppression is inconsistent: safe-sync exits only when aggregate additions and re-enables are zero, External ID exits when its selected field is unchanged, and the shared executor plus `apply-plan` otherwise PATCH their planned setups even when account membership is unchanged (`cmd/awssync/main.go:223-227`, `internal/app/external_id.go:241-242`, `internal/app/run.go:851-863`, `internal/app/apply_plan.go:144-147`).

### What the five commits reveal

- **CONFIRMED:** `b159af6` introduced a reusable limits helper but enforcement remained duplicated in main planned sync, preflight, and `apply-plan` (`internal/app/removal_limits.go:14-93`, `internal/app/run.go:307-320`, `internal/app/preflight.go:138-150`, `internal/app/apply_plan.go:118-130`).
- **CONFIRMED:** `fe4baf4` added per-account External IDs both inside the planner and through the pre-existing independent External ID writer, increasing the number of credential mutation semantics (`internal/app/run.go:1137-1158`, `internal/app/external_id.go:67-251`, `internal/app/external_id_file.go:13-96`).
- **CONFIRMED:** `ac15c6c` made NQE reconciliation additive through `PreserveMissing`, but retained authoritative omission-as-delete and made the shared builder re-enable every target account (`internal/app/run.go:1063-1076`, `internal/app/run.go:1228-1261`, `internal/app/run.go:1666-1672`).
- **CONFIRMED:** `2794e14` added a separate safe-sync orchestration layer around the same planner instead of adding a safety policy object and mutation gateway (`cmd/awssync/main.go:165-257`).
- **CONFIRMED:** `0c0dbd5` added the no-change exit to that CLI layer only, leaving the underlying executor unchanged (`cmd/awssync/main.go:223-227`, `internal/app/run.go:851-863`).

---

## 2. Deletion semantics

### All intentional and incidental removal/disable paths

| Removal or disable path | Trigger | Guards actually applied | Empty, partial, or stale source behavior |
|---|---|---|---|
| NQE prune through root CLI | Retired. Passing recognized `--prune-missing` returns an actionable error before credentials, NQE, planning, or apply. | No override exists. NQE policy construction returns only `Additive`, and planning rejects `CompleteInventory` for source `nqe`. | Empty, partial, stale, failed-collection, or wrong-organization observations cannot remove configured membership. |
| NQE prune through webhook | Retired. `serve-webhook --prune-missing` returns the same startup refusal. | No event, evidence flag, removal authorization, or ceiling can enable NQE deletion. | Event snapshots remain observed inventory and are additive regardless of apparent completeness. |
| Authoritative manifest sync | Configured ID omitted from the reviewed manifest (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:1063-1076`) | Generic confirmation/`--yes`; `--allow-removals`; both removal ceilings; pre-PATCH re-read. Candidate, org-evidence, and GovCloud NQE evidence checks are bypassed because the source is marked authoritative (`cmd/awssync/main.go:780-845`, `internal/app/run.go:307-350`) | Empty manifests and invalid/duplicate IDs fail before planning; a nonempty incomplete human-generated manifest is accepted as complete and removes omissions within bounds (`internal/app/account_manifest.go:21-59`). |
| `apply-plan` target omission | An account ID present in current state is missing from an arbitrary reviewed payload (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-114`) | `--yes`; `--allow-removals`; both ceilings; GovCloud removal always blocked; rollback file and pre-PATCH re-read (`cmd/awssync/main.go:488-536`, `internal/app/apply_plan.go:118-147`) | An empty `assumeRoleInfos` array is structurally accepted and can remove all commercial accounts if the explicit ceilings permit; there is no source evidence or completeness check (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-130`). |
| `apply-plan` disable | Account ID remains present but its `enabled` field changes false | Typed `Disable` classification; gateway destructive authorization and aggregate/per-setup budgets | Independent of inventory, but no longer a destructive-policy bypass (`internal/app/apply_plan.go`, `internal/app/apply_gateway.go`; fixed by `e854787`). |
| Stale read/modify/write overwrite | A concurrent actor adds/removes/edits accounts after the gateway equality re-read but before full-list PATCH (`internal/app/apply_gateway.go`) | Every writer performs the same non-atomic equality re-read; no path can send a revision precondition (`internal/api/client.go`) | Not inventory-dependent. A newly added concurrent account absent from the target can still be silently removed inside the final race window. |

No code path intentionally deletes the Forward setup object itself; setup mutations are POST for creation and PATCH for replacement/update (`internal/api/client.go:355-368`).

### Observed inventory, emptiness, and truncation

#### CRITICAL — CONFIRMED — ROOT CAUSE FIXED BY FEATURE RETIREMENT

The prior analysis treated pagination completeness as the missing safety proof. That was one real defect, but not the root cause. `network.cloudAccounts` is an observed snapshot view: collected accounts unioned with accounts visible through Organizations metadata. Authorization failures can be ignored and service failures can return a partial accumulated result. A clean final NQE page proves only that pagination over that observed view terminated; it provides no expected configured count, organization identity, collection-success contract, or account-lifecycle assertion.

The production measurements make the distinction concrete:

| network | configured | NQE rows | would have been deleted | enabled among them |
|---|---:|---:|---:|---:|
| 253234 | 978 | 10 | 968 | 968 |
| 253236 | 565 | 540 | 27 | 27 |

Accordingly:

- **CONFIRMED — FIXED:** NQE absence cannot authorize deletion at any cardinality. The root CLI, preflight, and webhook retain `--prune-missing` only to refuse it; the NQE policy constructor is additive-only; and an internal NQE snapshot paired with `CompleteInventory` is rejected.
- **CONFIRMED — RETAINED:** Phase 2a's pagination completeness characterization remains useful for detecting truncated observed results and reporting data quality. It is no longer a gate that can turn absence into removal.
- **CONFIRMED:** `sync-accounts` can remove omissions because its input is an explicit, complete, human-reviewed manifest. Empty manifests and invalid/duplicate IDs fail before planning; `ComputeDesired`, destructive authorization, both removal ceilings, rollback, re-read, and `GuardAndApply` remain in force.
- **CONFIRMED:** `apply-plan` can directly express an empty target list, subject to its explicit removal authorization and bounds for commercial setups. That explicit target payload is a separate reviewed-operation path, not an inference from NQE absence.

### Absence versus explicit deprovisioning

#### CRITICAL — CONFIRMED — FIXED FOR NQE; MANIFEST REMOVAL RETAINED

The domain distinguishes additive NQE absence (`Preserve`) from reviewed-manifest omission (`Remove`). Completeness metadata alone no longer selects the latter: `CompleteInventory` remains a legitimate policy kind only for the authoritative manifest path, while NQE construction and source validation prevent it from being selected for observed inventory. Explicit lifecycle tombstones and complete source-organization identity are still not modeled; the human review of the manifest is the removal assertion (`internal/app/domain.go`, `internal/app/reconcile.go`, `internal/app/account_manifest.go`).

The direct AWS discovery code does know active versus non-active status, but it is used for new setup creation rather than existing reconciliation; non-active accounts are skipped unless `includeSuspended` is set (`internal/awsorg/discover.go:84-107`, `internal/awsorg/discover.go:130-146`, `internal/app/run.go:376-542`).

---

## 3. Read-modify-write safety

### Is PATCH a full-list replacement?

#### CONFIRMED in the client contract

The production model serializes `assumeRoleInfos` as a complete array in `PatchPayload`; the planner rebuilds every target entry, and rollback also captures a complete array (`internal/api/client.go:89-105`, `internal/app/run.go:1141-1165`, `internal/app/run.go:1819-1849`). The architecture document explicitly calls the account list “full-state, not incremental,” and `apply-plan` detects omission as removal before sending the payload (`docs/architecture-flow.md:132-143`, `internal/app/apply_plan.go:108-130`).

#### CONFIRMED at the Forward server boundary

The Forward server is confirmed to apply incoming fields with tri-state merge semantics (`JsonProp<T>`) and set `assumeRoleInfos` only when present. In that case, `builder.assumeRoleInfos(roleInfos)` replaces the array; all other fields remain unset by omission (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateAwsAccountRequest.java:88-91`, `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java:73-81`). Top-level patching starts from `account.toBuilder()`, so omitted keys preserve existing values (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java:80-94`).

### Optimistic concurrency

#### CRITICAL — CONFIRMED: no client-visible CAS token; server replay makes contention deterministic

`PatchCloudAccount` sends a plain PATCH; request construction adds content type, accept, and Basic Auth only (`internal/api/client.go:355-363`, `internal/api/client.go:432-440`). `CloudAccount` contains no revision/version field and the PATCH function accepts no ETag or If-Match (`internal/api/client.go:76-105`, `internal/api/client.go:344-363`).

`CloudAccountService` updates accounts via `kvStore.getAndUpdate(...)` with a transform that may be retried (`~/src/fwd/app/src/main/java/com/forwardnetworks/cv/sources/cloud/CloudAccountService.java:204-235`). On contention, the service re-reads fresh state and faithfully re-applies the client's absolute full-list intent onto it. The clobber is therefore deterministic rather than probabilistic: a concurrent edit is not lost to unlucky timing, it is lost *because* the retry loop correctly replays stale intent over newer state.

All writers now capture an immutable baseline and `GuardAndApply` immediately re-GETs each selected setup before its PATCH, including External ID rotation (`internal/app/apply_gateway.go`, `internal/app/external_id.go`; fixed by `1828278` and `e854787`). This detects a change before that GET completes, but cannot protect the interval from the successful GET to the subsequent PATCH. The characterization race tests intentionally remain failing because no client-visible CAS token exists.

### Idempotency, retries, and partial failure

- **HIGH — CONFIRMED:** Reapplying an identical complete target is logically idempotent if no concurrent writer exists, because each retry sends the same serialized body; no application-level idempotency key makes that guarantee explicit (`internal/api/client.go:416-450`).
- **HIGH — CONFIRMED:** PATCH is classified as retryable on transport errors and 429/502/503/504 responses; if the server committed but the response was lost, the client sends the same body again without a revision or operation key (`internal/api/client.go:402-450`, `internal/api/client.go:460-492`).
- **HIGH — CONFIRMED:** A multi-setup plan is not atomic. `GuardAndApply` stops at the first conflict/PATCH error after any earlier successes. Since `1828278`, the returned result and atomically rewritten journal preserve `planned`, `pending`, `applied`, `conflicted`, and `failed` per-setup outcomes (`internal/app/apply_gateway.go`).
- **HIGH — CONFIRMED:** The durable journal makes partial completion inspectable, but automatic resume and rollback remain absent; an operator must use the journal and rollback artifact deliberately (`internal/app/apply_gateway.go`).
- **MEDIUM — CONFIRMED:** Rollback artifacts are written before every changed gateway apply, but rollback remains manual and uses the same non-transactional `apply-plan` path (`internal/app/apply_gateway.go`, `internal/app/apply_plan.go`, `docs/aws-account-sync-procedure.md:600-608`).
- **HIGH — CONFIRMED — FIXED (`e854787`):** External ID mutation now constructs a full typed target and uses `GuardAndApply`, which writes the pre-change rollback artifact, applied audit artifact, and result journal before PATCH (`internal/app/external_id.go`, `internal/app/apply_gateway.go`).
- **MEDIUM — CONFIRMED — FIXED (`1828278`):** `GuardAndApply` returns after journaling when every `ChangeSet` is empty, so every adapter centrally suppresses zero-diff PATCHes (`internal/app/apply_gateway.go`).

#### CONFIRMED: top-level omitted fields are preserved

`UpdateCloudAccountRequest` starts from `account.toBuilder()` and applies each present field via `ifPresent` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java:73-81`, `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java:80-94`). Unmodeled server fields remain unless explicitly modified by the request; omission in awssync payload therefore preserves existing values on these keys.

#### Server-side guard note

`UpdateAwsAccountRequest` has duplicate `assumeRoleInfos` account-ID validation and rejects a duplicate with `BadRequestException` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateAwsAccountRequest.java:63-69`), and it also rejects updating a single-account setup to multi-account (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateAwsAccountRequest.java:89`).

---

## 4. Edge cases not handled

### Inventory cardinality and completeness

- **HIGH — CONFIRMED — zero accounts:** NQE, manifest, and direct-onboarding zero-account sources fail; there is no explicitly authorized “empty authoritative desired set” model, while `apply-plan` can express the same outcome as arbitrary JSON (`internal/app/run.go:1097-1102`, `internal/app/account_manifest.go:38-40`, `internal/app/run.go:413-416`, `internal/app/apply_plan.go:58-79`).
- **MEDIUM — CONFIRMED — current setup has zero accounts:** the planner cannot derive a role name and skips the setup; External ID mutation rejects it, so the tool cannot repair an empty existing setup through its normal paths (`internal/app/run.go:1120-1126`, `internal/app/external_id.go:117-119`).
- **MEDIUM — CONFIRMED — one setup:** local NQE filtering is disabled when zero or one setup is requested, and setup-less rows are assigned wholesale to the sole setup; a query/filter regression can import unrelated AWS rows (`internal/api/client.go:302-318`, `internal/app/run.go:1326-1347`).
- **CRITICAL — CONFIRMED — FIXED BY RETIREMENT — partial nonempty observed inventory:** there is no manifest contract or total configured-account proof, so the former prune behavior interpreted ordinary observation gaps as removals. NQE reconciliation is now source-enforced additive; partial data can miss additions but cannot delete membership.
- **MEDIUM — CONFIRMED — pagination pathologies:** the client has no repeated-page/cursor guard or advertised total; an API that repeats a full page loops indefinitely, and an API that silently caps below 1000 produces a false complete result (`internal/api/client.go:19`, `internal/api/client.go:242-277`).
- **LOW — CONFIRMED — direct AWS pagination errors:** Organizations discovery safely returns an error on any account or parent page failure rather than applying its accumulated prefix, but no test covers a later-page failure (`internal/awsorg/discover.go:84-107`, `internal/awsorg/discover.go:148-164`, `internal/awsorg/discover_test.go:49-96`).

### Identity, duplication, and movement

- **HIGH — CONFIRMED — account moved between organizations/setups:** the desired row contains no source organization identity or move operation; each setup is patched independently, so a move across two selected setups can partially complete and leave the account in both or neither (`internal/app/run.go:20-39`, `internal/app/run.go:1104-1201`, `internal/app/run.go:851-863`).
- **MEDIUM — CONFIRMED — FIXED (`00b7e89`):** duplicate/conflicting discovered IDs are rejected by typed adapters instead of silently first-wins (`internal/app/adapters.go`).
- **MEDIUM — CONFIRMED — FIXED (`00b7e89`):** duplicate configured account identities are rejected consistently at the current-setup adapter boundary (`internal/app/adapters.go`).
- **MEDIUM — CONFIRMED — duplicate setup names:** `SetupID` is derived from setup name (`internal/app/run.go:1481`) and the route key in the Forward API is `accountName` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/controller/CloudAccountController.java:196-204`), so a later same-name setup overwrites the earlier one as a targeting collision (`internal/app/run.go:1474-1491`).
- **MEDIUM — CHANGED (Phase 1):** account IDs are now validated to exactly 12 digits across shared adapters (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/external_id.go:142-153`). This is a fail-closed change: malformed rows fail with operator-visible errors like `invalid AWS account ID "setup-a"; expected exactly 12 digits`, and a single malformed row can block a full sync on a large setup (`internal/app/run_test.go:748`).
- **MEDIUM — CONFIRMED — type/case/whitespace mismatch:** raw row extraction requires exact column keys and string values; numeric JSON IDs become empty, alternate key case is ignored, and setup matching is exact inside the planner even though interactive CLI selection canonicalizes case (`internal/app/run.go:1263-1289`, `internal/app/run.go:1412-1425`, `cmd/awssync/main.go:1685-1724`).
- **MEDIUM — CONFIRMED — FIXED (`00b7e89`):** when both account ID and role ARN are present, typed current-state adaptation asserts that their account components agree (`internal/app/adapters.go`, `internal/app/adapters_test.go`).
- **MEDIUM — CONFIRMED — FIXED (`fbf78bb`):** name drift is a typed `Rename` change and is no longer hidden behind membership-only no-op logic (`internal/app/reconcile.go`).

### Lifecycle and state

- **HIGH — CONFIRMED — suspended/closed accounts:** NQE planning has no lifecycle field and cannot distinguish suspension from query absence; direct AWS onboarding either omits non-active accounts or, with `includeSuspended`, creates them as ordinary enabled target entries (`internal/app/run.go:20-39`, `internal/awsorg/discover.go:84-107`, `internal/app/run.go:645-657`).
- **MEDIUM — CONFIRMED — disabled accounts absent from additive inventory:** because current entries are merged into the target and every emitted target is enabled, an additive run re-enables disabled accounts even when NQE did not return them (`internal/app/run.go:1228-1261`, `internal/app/run.go:1666-1672`).
- **MEDIUM — CONFIRMED — explicit disable intent:** only raw `apply-plan` can preserve or introduce `enabled:false` as desired state; the normal planner has no typed disable transition (`internal/app/apply_plan.go:58-79`, `internal/app/run.go:1666-1672`).

### External ID drift and rotation

- **HIGH — CONFIRMED:** External ID rotation changes Forward first/only; there is no verification that the matching AWS role trust policy already accepts the value and no coordinated two-phase rotation (`internal/app/external_id.go:161-251`).
- **HIGH — CONFIRMED — FIXED (`e854787`):** External ID now computes/classifies the target before gateway authorization and receives the common rollback artifact and concurrent-update recheck. AWS trust-policy readiness remains unverified (`internal/app/external_id.go`, `internal/app/apply_gateway.go`).
- **MEDIUM — CONFIRMED:** standard sync can also change External IDs from a CSV while its main diff reports membership/re-enable state rather than a typed per-account credential change, weakening review visibility (`internal/app/run.go:1137-1158`, `internal/app/run.go:1173-1201`).
- **MEDIUM — CONFIRMED:** mixed-ID setups require explicit assignments for new accounts, which safely fails closed, but there is no drift comparison to AWS or planned rotation window (`internal/app/run.go:1611-1664`).

### Ordering, time, and monitor/webhook behavior

- **HIGH — CONFIRMED — FIXED (current uncommitted webhook slice):** the worker resolves snapshot chronology and enforces an in-progress/applied watermark per network/setup both before admission and again before execution. Older events receive a non-2xx response or are discarded before `app.Run`; watermarks survive restart (`internal/webhook/server.go`, `internal/webhook/state.go`).
- **HIGH — CONFIRMED — FIXED (current uncommitted webhook slice):** queue-full rejection never creates an in-flight/dedupe record; a failed `app.Run` clears in-flight admission; only successful work enters the 24-hour completed-event map. Concurrent same-key deliveries wait for the first outcome, so failure is redeliverable without double-running successful work (`internal/webhook/server.go`, `internal/webhook/state.go`).
- **MEDIUM — CONFIRMED — FIXED (current uncommitted webhook slice):** dedupe keys contain type, network, snapshot, sorted setup scope, and event ID and are persisted across restart in the webhook state file (`internal/webhook/state.go`).
- **HIGH — CONFIRMED — FIXED (current uncommitted webhook slice):** a configured network must equal the event network, event setup IDs must be a subset of configured setup IDs, and an omitted event setup scope inherits the configured set. Apply-enabled servers refuse to start unless a network and both Basic Auth values are configured; requests must authenticate (`internal/webhook/server.go`, `cmd/awssync/main.go`).
- **MEDIUM — CONFIRMED — PARTIALLY FIXED (current uncommitted webhook slice):** explicit snapshot IDs now use the snapshot list to enforce `MaxSnapshotAge`; the pre-existing future-timestamp behavior remains because validation still only rejects age greater than the maximum (`internal/app/run.go`).
- **MEDIUM — CONFIRMED — FIXED (`fbf78bb`):** payload planning uses an injected policy planning instant, so preview/apply no longer derive region test time independently (`internal/app/domain.go`, `internal/app/reconcile.go`).
- **LOW — CONFIRMED — filename ordering:** default artifact names use second-level timestamps, so multiple runs in one second can address the same filename and the later atomic rename can replace the earlier artifact (`internal/app/run.go:739-751`, `internal/app/run.go:1872-1970`).
- **MEDIUM — CONFIRMED — monitor consistency:** `Status` fetches latest and the list in separate requests; `Wait` compares states case-sensitively, recognizes only `FAILED` and `ARCHIVED` as terminal, and polls forever for an absent snapshot until context cancellation (`internal/monitor/monitor.go:25-51`, `internal/monitor/monitor.go:54-100`).

---

## 5. Guard placement

### Guard matrix

| Guard | Root NQE | `safe-sync` | Webhook | Manifest sync | `apply-plan` | External ID |
|---|---:|---:|---:|---:|---:|---:|
| Typed desired-state/change validation | Yes | Yes | Yes, through root NQE adapter | Yes, through manifest adapter | Yes, payload classified against typed current setup | Yes, typed External ID operations classified against current setup |
| Preflight required | No | Yes | No | No | No | No |
| Apply authorization bound to immutable intent digest | Yes | Yes | Yes, unattended actor | Yes | Yes | Yes |
| Removal/disable authorization and ceilings | Additive/no removal | Additive invariant | Additive/no removal | Yes | Yes | Applicable if classified destructive |
| Candidate/org/completeness evidence | Diagnostic only; never authorizes removal | Diagnostic/additive | Diagnostic only; never authorizes removal | Reviewed manifest completeness policy | Compatibility allowance for operator-authored file; GovCloud still blocked | Explicit operation, not absence-based |
| Rollback + applied audit artifact | Yes | Yes | Yes | Yes | Yes | Yes |
| Last-moment equality re-read | Yes | Yes | Yes | Yes | Yes | Yes |
| Atomic CAS/version | No (`internal/api/client.go:355-363`) | No | No | No | No | No |
| Zero-diff PATCH suppression | Gateway | Gateway | Gateway | Gateway | Gateway | Gateway |
| Durable per-setup result journal | Yes | Yes | Yes | Yes | Yes | Yes |

### Bypasses

1. **HIGH — CONFIRMED — PARTIALLY FIXED (`e854787`):** `apply-plan` still bypasses source inventory/candidate evidence by design, but its payload is now typed/classified and `Disable` and `Remove` share gateway authorization and budgets. The compatibility adapter explicitly records its lack of NQE evidence (`internal/app/apply_plan.go`, `internal/app/apply_gateway.go`).
2. **HIGH — CONFIRMED — FIXED (`e854787`):** External ID apply no longer bypasses common rollback, final equality re-read, intent digest, zero-diff suppression, or journaling (`internal/app/external_id.go`, `internal/app/apply_gateway.go`).
3. **HIGH — CONFIRMED — RESIDUAL:** webhook still bypasses preflight and interactive per-event confirmation. Apply mode requires the launch-time `--yes` automation decision, gateway authorization, and now authenticated requests; unattended destructive work additionally requires `--allow-unattended-destructive` (`cmd/awssync/main.go`, `internal/webhook/server.go`).
4. **HIGH — CONFIRMED — FIXED (current uncommitted webhook slice):** webhook events can narrow configured setup scope but cannot replace a configured network or expand a configured setup allowlist (`internal/webhook/server.go`).
5. **HIGH — CONFIRMED:** `sync-accounts` bypasses candidate and organization evidence by asserting a human manifest is authoritative; omission remains destructive (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:321-333`).
6. **HIGH — CONFIRMED — MITIGATED (`1828278`):** noninteractive root/CI with `--yes` does not require preflight, but gateway policy blocks destructive work unless `--allow-unattended-destructive` is also explicit. Additive automation remains allowed (`cmd/awssync/main.go`, `internal/app/apply_gateway.go`).
7. **HIGH — CONFIRMED — FIXED (`1828278`):** every gateway authorization is checked against the immutable `ApplyIntent` digest; standard interactive preview copies its expected plan digest into apply (`cmd/awssync/main.go`, `internal/app/apply_gateway.go`).
8. **MEDIUM — CONFIRMED — FIXED (current uncommitted webhook slice):** explicit snapshots, including webhook event snapshots, are looked up and checked against `MaxSnapshotAge` (`internal/app/run.go`).
9. **MEDIUM — CONFIRMED — FIXED (`1828278`):** empty `ChangeSet` is centrally suppressed in `GuardAndApply` for every caller (`internal/app/apply_gateway.go`).
10. **MEDIUM — CONFIRMED:** a positive candidate or OU count bypasses the no-evidence block without proving inventory completeness (`internal/app/run.go:1427-1455`).

Since `1828278`/`e854787`, `GuardAndApply` is a true mutation chokepoint: it contains the only production call to `api.PatchCloudAccount`, and `internal/app/patch_chokepoint_test.go` fails if another caller appears. Preflight remains an advisory adapter-specific layer; mutation authorization, destructive classification, ceilings, evidence, rollback, last-moment re-read, zero-diff suppression, PATCH, and result journaling are gateway responsibilities.

---

## 6. Test coverage

### What is covered well enough to be meaningful

- **CONFIRMED:** Main planner tests exercise additive preservation, direct rejection of `CompleteInventory` for NQE snapshots, manifest completeness, and malformed IDs (`internal/app/run_test.go`, `internal/app/reconcile_test.go`).
- **CONFIRMED:** Apply tests cover rollback output and reviewed-payload hash mismatch; supported removal opt-in and both blast-radius dimensions are exercised through authoritative manifest and `apply-plan` paths. Former NQE removal/evidence cases are explicitly marked obsolete rather than silently deleted (`internal/app/account_manifest_test.go`, `internal/app/run_test.go`, `internal/app/apply_plan_test.go`).
- **CONFIRMED:** `apply-plan` tests cover GovCloud rejection, percentage/count bounds, and a setup change observed by the second GET before PATCH (`internal/app/apply_plan_test.go:72-251`).
- **CONFIRMED:** safe-sync tests cover preflight/preview/apply, multiple setups, noninteractive confirmation, zero-change skip, and failed preflight (`cmd/awssync/main_test.go:143-419`).
- **CONFIRMED:** External ID tests cover set/clear, selected-account scoping, CSV actions, preservation of other entries, and unsafe input rows (`internal/app/external_id_test.go:16-229`).
- **CONFIRMED:** API tests cover normal pagination, setup filtering, selected retries, and non-retry of create (`internal/api/client_test.go:13-155`, `internal/api/client_test.go:253-364`).
- **CONFIRMED:** Phase 0 characterization covers the final GET/PATCH race, partial multi-setup failure, disable classification, External ID recovery/concurrency, and webhook loss/order/scope. The incomplete-nonempty and undetectable-short-page NQE deletion premises are explicitly obsolete because NQE pruning is unreachable; Phase 2a completeness tests remain elsewhere. All Phase 0 guard constants remain `false` (`internal/*/architecture_failure_test.go`).
- **CONFIRMED:** Gateway tests cover zero-diff suppression, plan-digest authorization, destructive budgets/evidence, last-moment conflict, rollback, and durable partial journals. A source scan test enforces exactly one production `PatchCloudAccount` caller (`1828278`, `e854787`, `internal/app/apply_gateway_test.go`, `internal/app/patch_chokepoint_test.go`).
- **CONFIRMED:** Webhook tests cover apply-mode authentication and the guarded six-case delivery/scope contract; explicit snapshot freshness has direct fresh/stale tests (`internal/webhook/server_test.go`, `internal/webhook/architecture_failure_test.go`, `internal/app/snapshot_freshness_test.go`).

The suite is therefore not “mostly happy paths.” It verifies many of the reactive safeguards. Its weakness is that it tests each safeguard in the path where it was added, not the system-level invariants across every writer.

### Highest-value missing tests, in priority order

1. **CRITICAL — unresolved CAS characterization:** the final GET/PATCH race tests now exist and must continue to demonstrate clobber until Forward exposes a revision token. They are evidence of a missing contract, not tests to make green by weakening the assertion (`internal/app/architecture_failure_test.go`, `internal/api/architecture_failure_test.go`).
2. **HIGH — ambiguous PATCH retry:** simulate server commit followed by connection loss and a concurrent edit before retry. No idempotency/revision contract currently prevents overwrite (`internal/api/client.go`).
3. **HIGH — cross-setup move:** fail either PATCH order for an account moving from setup A to B and require an explicit transaction/move invariant that prevents duplicate or missing final ownership (`internal/app/reconcile.go`, `internal/app/apply_gateway.go`).
4. **HIGH — partial-operation recovery:** durable per-setup results now exist, but explicit resume and verified rollback commands still need crash/restart tests (`internal/app/apply_gateway.go`).
5. **MEDIUM — account identity property/fuzz tests:** retain exact 12-digit, whitespace, numeric JSON, conflicting duplicate-page, account/ARN disagreement, and duplicate setup-name coverage beyond the current table tests (`internal/app/domain_test.go`, `internal/app/adapters_test.go`).
6. **MEDIUM — lifecycle tests:** active, suspended, closing, closed, moved, and unknown states need explicit typed decisions rather than absence-based pruning (`internal/awsorg/discover.go`, `internal/app/domain.go`).
7. **MEDIUM — snapshot/monitor tests:** future timestamps, missing explicit snapshots through the full `Run` path, lowercase/unknown terminal states, list pagination, and non-atomic latest/list changes remain (`internal/app/run.go`, `internal/monitor/monitor.go`).
8. **MEDIUM — Organizations pagination tests:** multiple account/parent pages, empty discovery, suspended inclusion, duplicate IDs, and second-page failure remain high-value (`internal/awsorg/discover.go`).

---

## 7. Recommended target architecture

### Design goal

Replace mode-specific mutation logic with one domain pipeline:

```text
Source adapter
  -> typed InventorySnapshot + Provenance/Completeness
  -> ComputeDesired(CurrentSetup, InventorySnapshot, ReconcilePolicy)
  -> typed ChangeSet + immutable ApplyIntent
  -> one GuardAndApply gateway
  -> CAS-protected API write + durable per-setup result
```

Phases 1-3 implemented the typed adapter, pure diff, immutable intent, single gateway, and durable result portions. “CAS-protected API write” remains an unavailable target because Forward exposes no token; the shipped fallback is an immediate equality re-read plus a prohibition on unattended destructive work unless the operator adds `--allow-unattended-destructive`.

### Layer 1: typed domain model

Phase 1 (`00b7e89`) introduced the typed domain/adapters, and Phase 2a (`8cf4ef9`) added completeness provenance. Remaining lifecycle/server-revision gaps are called out explicitly:

- `AccountID` validates exactly 12 digits once; `SetupID` has a canonical comparison form; `Partition` is an enum; `RoleARN` validates partition and asserts its account component matches `AccountID` (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/run.go:1708-1714`).
- `AccountLifecycle` is `Active | Suspended | Closing | Closed | Unknown`; `DesiredMembership` is `PresentEnabled | PresentDisabled | ExplicitlyRemove | Preserve`, so absence alone is not an action (`internal/awsorg/discover.go:130-146`, `internal/app/run.go:1063-1076`).
- `InventorySnapshot` includes source kind, network, snapshot ID/time, organization ID, selected setup scope, page/completeness proof, expected/observed counts, collection status, and lifecycle rows; the current NQE output lacks most of these fields (`internal/app/run.go:20-39`, `internal/api/client.go:227-277`).
- `CurrentSetup` includes a revision/ETag and preserves opaque server fields required for round-trip safety; current structs have neither (`internal/api/client.go:76-105`, `internal/api/client.go:355-363`).
- `ChangeSet` classifies `Add`, `Enable`, `Disable`, `Remove`, `Rename`, `RotateExternalID`, `ChangeRole`, and setup-metadata changes; current diffing is ID-only in `apply-plan` and membership/re-enable-only in the main planner (`internal/app/apply_plan.go:108-130`, `internal/app/run.go:1135-1158`).
- `ReconcilePolicy` remains tagged as `Additive`, `CompleteInventory`, or `ExplicitOperations`. `CompleteInventory` is retained for the legitimate reviewed-manifest caller; NQE uses a dedicated additive constructor and source validation rejects pairing NQE with `CompleteInventory`, preventing the retired boolean from being recreated (`internal/app/run.go`, `internal/app/account_manifest.go`).

Raw NQE maps and JSON/CSV files should exist only inside adapters. They must normalize or reject duplicate/conflicting IDs and exact column/type errors before reaching the domain planner (`internal/app/run.go:1263-1324`, `internal/app/run.go:1457-1472`).

### Layer 2: one desired-state and diff engine

Phase 2b (`fbf78bb`) made desired-state and diff computation pure and deterministic: no API calls, file writes, or hidden `time.Now`; inputs include an explicit planning instant. Every mutation adapter uses it or typed payload classification:

- NQE and manifests supply inventory adapters.
- `safe-sync` supplies `Additive` policy.
- root/webhook supply an explicitly selected policy.
- External ID rotation supplies explicit per-account credential operations against the same typed current state.
- `apply-plan` deserializes a versioned `ApplyIntent`, not an arbitrary patch map.

`GuardAndApply` suppresses PATCH when every `ChangeSet` is empty. A transactional unique-ownership invariant for cross-setup moves remains future work.

### Layer 3: one guard chokepoint

Every account-list PATCH is now impossible except through `GuardAndApply(intent, authorization)`, test-enforced by `internal/app/patch_chokepoint_test.go`. The gateway enforces:

1. Exact account/ARN/partition uniqueness and consistency for current and target (`internal/app/run.go:1611-1664`, `internal/app/run.go:1708-1714`).
2. A complete, scope-matched inventory proof before any absence-based removal; otherwise only explicit tombstones can remove (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
3. Typed destructive classification covering both `Remove` and `Disable`, not ID omission only (`internal/app/apply_plan.go:108-130`).
4. Aggregate/per-setup ceilings and explicit destructive authorization for all writers (`internal/app/removal_limits.go:24-80`).
5. GovCloud/source-specific evidence rules as policy, not CLI conditionals (`internal/app/run.go:321-333`).
6. Plan digest bound to the available baseline state, source snapshot/completeness proof, policy, and target payload; authorization actor and policy are durably recorded. A server revision cannot be bound because none exists (`internal/app/apply_gateway.go`).
7. Central zero-diff exit, rollback capture, applied audit, and redacted credential reporting (`internal/app/apply_gateway.go`).
8. CAS with `If-Match`/version. If the Forward API cannot provide CAS, treat account-list PATCH as unsafe for unattended destructive use; a last-second GET/hash is only a documented weak fallback (`internal/api/client.go:355-363`, `internal/app/run.go:1851-1870`).
9. An idempotency key for retryable writes, or no automatic retry after ambiguous transport failure (`internal/api/client.go:402-450`).
10. A durable result journal recording `planned`, `applied`, `conflicted`, `failed`, and `pending` per setup (`internal/app/apply_gateway.go`). Automatic resume remains future work.

Confirmation is now a user-interface adapter that issues `ApplyAuthorization` for an immutable intent. `--yes` is a recorded automation authorization; destructive unattended use additionally requires `--allow-unattended-destructive` (`cmd/awssync/main.go`, `internal/app/apply_gateway.go`).

### Layer 4: safe event processing

Webhook handling now keys successful dedupe by event ID plus network/snapshot/setup scope, persists completed keys and per-network/setup watermarks, intersects event scope with configured scope, makes queue rejection and failed jobs redeliverable, rejects older snapshots, and reaches mutation only through `app.Run` and the shared gateway (`internal/webhook/server.go`, `internal/webhook/state.go`). Bounded retry/dead-letter processing and a crash-recoverable on-disk pending queue remain future work; callers must redeliver after a failed accepted job.

Monitor/status should consume the same snapshot ordering model, normalize states, expose missing/terminal outcomes, and avoid presenting separately fetched “latest” and “list” as one atomic observation (`internal/monitor/monitor.go:25-100`).

### Required invariants

The following should be executable assertions at domain and gateway boundaries:

1. A target contains unique exact-12-digit account IDs, and each ID agrees with its role ARN (`internal/app/account_manifest.go:14-50`, `internal/app/run.go:1708-1714`).
2. Every account belongs to at most one selected setup after a multi-setup transaction (`internal/app/run.go:1104-1201`).
3. Absence never produces `Remove` without a complete, matching source proof or explicit tombstone (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
4. `Disable` and `Remove` are both destructive and consume the same authorization/budget (`internal/app/apply_plan.go:108-130`).
5. Additive policy can only add, enable when explicitly requested by policy, or update separately authorized fields; it cannot infer deletion (`internal/app/run.go:1063-1076`, `internal/app/run.go:1228-1261`).
6. The applied target, baseline revision, evidence, and policy exactly match the approved intent (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:237-240`).
7. Empty `ChangeSet` never makes a network mutation (`cmd/awssync/main.go:223-227`, `internal/app/run.go:851-863`).
8. Every mutation has a durable pre-state, target digest, authorization record, and per-setup result, including External ID; a server-confirmed post-state and automatic recovery remain absent (`internal/app/apply_gateway.go`, `internal/app/external_id.go`).
9. A write conflict never silently retries against a newer baseline (`internal/api/client.go:402-450`).
10. A webhook cannot expand configured network/setup scope or move a setup backward to an older snapshot (`internal/webhook/server.go`, `internal/webhook/state.go`).

### Phased refactor plan

| Phase | Work | Risk | Exit criterion |
|---|---|---|---|
| 0. Characterize destructive behavior — **DONE (`09d4d48`)** | Guarded race, partial inventory, disable, webhook, External ID, and partial-apply characterizations exist | **LOW** | Complete; impossible no-CAS expectations intentionally remain failing when enabled. |
| 1. Introduce domain types and adapters — **DONE (`00b7e89`)** | Typed IDs, lifecycle/provenance adapters, and conflict rejection | **MEDIUM** | Complete; malformed input now fails closed. |
| 2. Build pure desired-state/diff engine — **DONE (`8cf4ef9`, `fbf78bb`)** | Completeness-gated absence semantics, tagged policy, typed `ChangeSet`, injected planning time | **MEDIUM** | Complete. |
| 3. Create `GuardAndApply` gateway — **DONE (`1828278`, `e854787`)** | Central no-op, destructive policy, evidence, ceilings, digest authorization, rollback/audit, last re-read, PATCH, and journal | **HIGH** | Complete; exactly one production PATCH caller is test-enforced. |
| 4. Add concurrency/idempotency contract — **CLOSED BY FINDING** | Forward has no client-visible revision token; `If-Match` cannot be implemented. `1828278` shipped the weak last re-read plus `--allow-unattended-destructive` mitigation | **HIGH / external dependency** | Closed pending Forward API change; race characterizations must keep failing. |
| 5. Make multi-setup and webhook execution durable — **DONE (current uncommitted webhook slice)** | Per-setup result journal shipped in `1828278`; schema-v2 webhook state now adds pre-ack pending persistence, queued/in-flight restart recovery, bounded exponential retry, and visible dead-letter records to durable dedupe/watermarks, authentication, scope intersection, and monotonic ordering | **MEDIUM-HIGH** | Complete; crash/restart, retry exhaustion, v1 upgrade, admission-write failure, and unchanged guard-flipped webhook characterizations pass. |
| 6. Remove legacy paths and flags | Delete direct External ID/apply-plan writers, boolean combinations, and duplicate CLI safeguards after all callers use typed intents (`internal/app/run.go:48-76`, `cmd/awssync/main.go:373-403`) | **LOW-MEDIUM**: CLI compatibility | One planner, one guard gateway, one writer; deprecated flags map to explicit policy during a documented transition. |
| 7. Correct documentation and operating procedure | Align rollback, webhook auth/scope, completeness, CAS, and failure recovery claims with the implemented contract (`README.md:178-188`, `docs/aws-account-sync-procedure.md:438-458`) | **LOW** | No safety claim is broader than an enforced gateway invariant and its test. |

---

## Prioritized action list

1. **P0 / CRITICAL — MITIGATED (`8cf4ef9`, `1828278`):** absence-based pruning now requires completeness proof, and unattended destructive work additionally requires `--allow-unattended-destructive`. Candidate/OU evidence is still not a proof of source correctness (`internal/app/reconcile.go`, `internal/app/apply_gateway.go`).
2. **P0 / CLOSED:** Full-list PATCH has no client-visible `ETag`/version/If-Match path. Phase 4 is closed pending Forward API changes; preserve the failing race characterizations and the unattended-destructive policy (`internal/api/client.go`, `internal/app/apply_gateway.go`).
3. **P0 / HIGH — CLOSED (`e854787`):** `apply-plan` disable is typed destructive work and consumes the same authorization and budgets as removal (`internal/app/apply_plan.go`, `internal/app/apply_gateway.go`).
4. **P0 / HIGH — CLOSED (current uncommitted webhook slice):** apply-mode authentication, configured-scope intersection, failure redelivery, durable scoped dedupe/watermarks, monotonic snapshot ordering, and explicit-snapshot freshness are enforced (`internal/webhook/server.go`, `internal/webhook/state.go`, `internal/app/run.go`).
5. **P1 / HIGH — MOSTLY CLOSED (`09d4d48`):** the failure-injection characterizations exist. Add the still-missing ambiguous transport retry and do not make the no-CAS tests pass by weakening them (`internal/*/architecture_failure_test.go`).
6. **P1 / HIGH — CLOSED (`00b7e89`, `8cf4ef9`, `fbf78bb`):** typed IDs, provenance/completeness, desired membership, tagged policies, and field-level `ChangeSet` are the production pipeline.
7. **P1 / HIGH — CLOSED (`1828278`, `e854787`):** immutable `ApplyIntent` plus `GuardAndApply` is the test-enforced single mutation gateway (`internal/app/patch_chokepoint_test.go`).
8. **P1 / HIGH — PARTIALLY CLOSED (`e854787`):** External ID uses the gateway with digest authorization, rollback, re-read, and journal. Atomic CAS and AWS trust-policy readiness verification remain unavailable/unimplemented (`internal/app/external_id.go`).
9. **P1 / HIGH — PARTIALLY CLOSED (`1828278`):** per-setup partial outcomes are durable; explicit resume and verified rollback commands remain (`internal/app/apply_gateway.go`).
10. **P2 / MEDIUM — CLOSED (`fbf78bb`, `1828278`):** planning time is deterministic, zero-diff suppression is central, and authorization is bound to the available baseline/evidence/policy/target digest. A server revision cannot be included until Forward supplies one.
11. **P2 / MEDIUM:** Finish source-scope/pagination hardening and add cross-setup move invariants (`internal/api/client.go`, `internal/app/reconcile.go`).
12. **P2 / MEDIUM — CLOSED (current uncommitted webhook slice):** Phase 5 operations now include crash-recoverable pending webhook jobs, bounded retries/dead-letter status, and the existing durable per-setup result journal. Operator documentation covers authentication, state-file ownership, inspection, and dead-letter drain/discard procedures.
