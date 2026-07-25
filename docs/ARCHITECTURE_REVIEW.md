# Architecture Review: `awssync`

Review date: 2026-07-25  
Repository state reviewed: `0c0dbd5` (`forwardnetworks/aws-sync`)

## Executive summary

- **CRITICAL — CONFIRMED:** `awssync` does not have one mutation model or one safety chokepoint; it has a shared NQE/manifest planner plus independent `apply-plan`, External ID, and setup-creation writers (`internal/app/run.go:250-373`, `internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:67-251`, `internal/app/run.go:376-542`).
- **CRITICAL — CONFIRMED:** NQE pruning equates “not present in this query result” with “remove from the setup”; there is no completeness token, expected account count, organization identity, or explicit deprovisioning event in the input model (`internal/app/run.go:1063-1076`, `internal/app/run.go:1129-1136`, `internal/api/client.go:227-277`).
- **CRITICAL — CONFIRMED:** A nonempty but truncated NQE result can therefore remove most configured accounts when pruning and sufficiently broad ceilings are enabled; one candidate or OU row is treated as positive organization evidence (`internal/app/run.go:1427-1455`, `internal/app/run.go:1716-1735`, `internal/app/removal_limits.go:24-80`).
- **CRITICAL — CONFIRMED:** A truly empty NQE result is rejected, so zero rows do not directly become “delete everything”; this protection does not cover a one-row or otherwise partial result (`internal/app/run.go:1084-1102`).
- **CRITICAL — CONFIRMED:** The client reads a setup, constructs a complete `assumeRoleInfos` array, and PATCHes it without `ETag`, version, `If-Match`, or another atomic compare-and-swap token (`internal/api/client.go:76-105`, `internal/api/client.go:344-363`, `internal/api/client.go:432-440`).
- **CRITICAL — CONFIRMED:** The pre-PATCH re-read is only a time-of-check check; a Forward UI edit after that GET and before the PATCH can still be overwritten (`internal/app/run.go:337-356`, `internal/app/run.go:1851-1870`).
- **HIGH — CONFIRMED:** `apply-plan` classifies danger only by missing account IDs; a reviewed payload can keep every ID but set every account to `enabled:false` without `--allow-removals` or removal ceilings (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-130`).
- **HIGH — CONFIRMED:** External ID rotation is a separate full-list read/modify/PATCH path with no rollback payload, final re-read, revision check, or plan-bound confirmation (`cmd/awssync/main.go:260-306`, `internal/app/external_id.go:109-123`, `internal/app/external_id.go:205-251`).
- **HIGH — CONFIRMED:** Standard interactive sync previews and confirms one computation, then recomputes without passing the reviewed payload hash; only `safe-sync` binds apply to the preview digest (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:213-240`).
- **HIGH — CONFIRMED:** Webhook jobs call `app.Run` directly, so they bypass the preflight command and any per-job confirmation; startup `--yes` is the only confirmation (`cmd/awssync/main.go:847-887`, `internal/webhook/server.go:167-193`).
- **HIGH — CONFIRMED:** A webhook event replaces the configured network and setup scope rather than intersecting with it, and Basic Auth is optional when no webhook credentials are configured (`internal/webhook/server.go:111-165`, `internal/webhook/server.go:167-180`).
- **HIGH — CONFIRMED:** Webhook deduplication records an event before queue admission and before successful processing; queue-full and failed-job retries can be acknowledged as duplicates and lost (`internal/webhook/server.go:139-148`, `internal/webhook/server.go:180-215`).
- **HIGH — CONFIRMED:** The webhook has no monotonic snapshot rule, so an older delayed event can reconcile after a newer event; this is destructive if the daemon was started with pruning and removal authorization (`internal/webhook/server.go:167-193`, `cmd/awssync/main.go:866-887`).
- **HIGH — CONFIRMED:** Multi-setup apply is a sequential PATCH loop with no transaction or durable progress record; failure on setup N leaves earlier setups changed and later setups untouched (`internal/app/run.go:851-863`, `internal/app/run.go:356-359`).
- **HIGH — CONFIRMED:** HTTP PATCH is automatically retried after transport and selected status failures, but no idempotency key or revision precondition is sent (`internal/api/client.go:402-450`, `internal/api/client.go:460-492`).
- **HIGH — CONFIRMED:** `safe-sync` is genuinely additive with respect to membership and refuses its own preview if it contains removals, but those guarantees live in its CLI orchestration rather than the mutation boundary (`cmd/awssync/main.go:165-240`, `internal/app/run.go:1063-1076`).
- **HIGH — CONFIRMED:** `sync-accounts` treats a reviewed manifest as authoritative and turns omission into removal; it bypasses NQE candidate and organization-evidence checks by setting `AuthoritativeInput` (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:321-333`).
- **HIGH — CONFIRMED:** There is no domain distinction between “absent,” “suspended,” “closed,” “moved,” and “explicitly deprovisioned” in the reconciliation rows; the planner consumes raw string-keyed maps containing only ID/name/setup/evidence fields (`internal/app/run.go:20-39`, `internal/app/run.go:1263-1311`).
- **MEDIUM — CONFIRMED:** The NQE paginator stops on any short page and has no total-count, completeness marker, repeated-page detection, or maximum-page guard (`internal/api/client.go:227-277`).
- **MEDIUM — CONFIRMED:** In single-setup mode, local filtering is disabled and rows without setup identity are assigned to that setup, increasing the damage from a saved query or server-side filter that returns overbroad data (`internal/api/client.go:302-318`, `internal/app/run.go:1326-1347`).
- **MEDIUM — CONFIRMED:** Duplicate discovered IDs are silently first-wins, while duplicate configured IDs are rejected only later in External ID preservation; conflicting duplicate input is not surfaced consistently (`internal/app/run.go:1457-1472`, `internal/app/run.go:1611-1628`).
- **MEDIUM — CHANGED (Phase 1):** The shared domain now validates exactly 12 digits in NQE parsing as the account-ID contract; this fails previously lenient inputs consistently and is a deliberate fail-closed availability tradeoff (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/external_id.go:142-153`).
- **MEDIUM — CONFIRMED:** Additive reconciliation re-enables every disabled account retained in the target, including configured accounts absent from the NQE result (`internal/app/run.go:1228-1261`, `internal/app/run.go:1666-1672`).
- **MEDIUM — CONFIRMED:** Explicit snapshot IDs skip freshness validation, including webhook-supplied snapshots; a stale delayed event is not rejected by `MaxSnapshotAge` (`internal/app/run.go:754-775`, `internal/webhook/server.go:167-180`).
- **MEDIUM — CONFIRMED:** Generated payloads can be time-dependent because a zero region `TestInstant` is replaced with `time.Now()`, making preview/apply digest stability depend on current setup data (`internal/app/run.go:1765-1781`).
- **MEDIUM — CONFIRMED:** `status` performs non-atomic “latest” and “list” reads, while `wait` has no monotonicity, paginated snapshot listing, unknown-terminal-state, or missing-snapshot handling beyond polling until context cancellation (`internal/api/client.go:334-342`, `internal/monitor/monitor.go:25-51`, `internal/monitor/monitor.go:54-100`).
- **MEDIUM — CONFIRMED:** The test suite contains meaningful removal, GovCloud, bounds, hash, and pre-PATCH-change tests; it is not merely happy-path coverage (`internal/app/run_test.go:389-433`, `internal/app/run_test.go:826-863`, `internal/app/run_test.go:931-1302`, `internal/app/apply_plan_test.go:72-251`).
- **HIGH — CONFIRMED:** The highest-risk adversarial cases remain untested: an edit in the final GET/PATCH race window, partial multi-setup apply, incomplete nonempty inventory, disabling through `apply-plan`, webhook retry loss/order, and External ID concurrency (`internal/app/apply_plan_test.go:209-251`, `internal/webhook/server_test.go:18-185`, `internal/app/external_id_test.go:16-229`).
- **MEDIUM — CONFIRMED:** Documentation says every apply writes rollback data, but External ID apply writes only an audit payload and the procedure documents manual reversal instead (`README.md:178-188`, `internal/app/external_id.go:241-251`, `docs/aws-account-sync-procedure.md:438-458`).
- **HIGH — CONFIRMED:** The last five commits added safety at individual seams—removal bounds, External ID preservation, additive mode, safe-sync orchestration, and a safe-sync zero-change shortcut—rather than replacing the divergent writers with one guarded mutation engine (`internal/app/removal_limits.go:14-93`, `internal/app/external_id.go:67-251`, `internal/app/run.go:1063-1076`, `cmd/awssync/main.go:165-240`).
- **TARGET:** All modes should produce one typed `DesiredSetup`, one typed field-level `ChangeSet`, and one immutable `ApplyIntent`; every PATCH must pass one guard/CAS/audit gateway (`internal/app/run.go:955-980`, `internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:62-251`).
- **TARGET:** Absence must not mean deletion unless the source proves completeness and organization/setup identity, or supplies an explicit deprovision tombstone (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
- **TARGET:** Confirmation, automation authorization, removal ceilings, zero-diff skip, rollback, concurrency control, retry policy, and result journaling belong in the single apply gateway, not in CLI and webhook call sites (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:165-240`, `internal/webhook/server.go:167-193`).

## Corrections (2026-07-25)

- **2026-07-25:** `SUSPECTED` finding at the Forward boundary on unmodeled field loss is corrected to `CONFIRMED` top-level merge semantics with preserved omissions, based on `UpdateCloudAccountRequest.applyTo` in `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateCloudAccountRequest.java`.
- **2026-07-25:** `SUSPECTED` behavior for `assumeRoleInfos` merge-vs-replace was updated to **CONFIRMED** replace-when-present; the field is set from the parsed request array in `UpdateAwsAccountRequest.applyTo` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/json/cloud/UpdateAwsAccountRequest.java:88-91`).
- **2026-07-25:** Concurrency findings were corrected: no client-visible ETag/version or `If-Match` contract exists on `PatchCloudAccount`, and Forward’s internal update path uses a `kvStore.getAndUpdate` retry loop that can deterministically reapply stale intent onto fresh state (`~/src/fwd/app/src/main/java/com/forwardnetworks/cv/sources/cloud/CloudAccountService.java:204-235`). Phase 4 is therefore not blocked by ambiguity; it is closed pending API contract change and policy controls.
- **2026-07-25:** Additional confirmed server-side behavior now recorded: duplicate `assumeRoleInfos` account IDs are rejected with `BadRequestException`, and single-account setups cannot be updated to multi-account.
- **2026-07-25:** Operational facts were added: network `253234` has `978` accounts against `PageLimit = 1000` (22 accounts of headroom before truncation becomes immediate), and setup identity is targeting-name based on both `run` and API route binding (`internal/api/client.go:19`, `~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/controller/CloudAccountController.java:196-204`).
- **2026-07-25:** Confirmed that `regionToProxyServerId` is currently preserved by omission and explicitly copied from current setup state before patch payload construction (`internal/app/run.go:1837`), matching observed behavior despite `collect`-field omissions.
- **2026-07-25:** Phase 1 deliberately made account-ID parsing fail-closed, and the tradeoff is recorded as explicit risk: one malformed NQE row now fails the whole plan instead of being silently skipped. Skipping rows is the mechanism by which a partial inventory becomes a deletion, so failing closed is the intended behavior — but on a large setup a single bad row is a full sync outage.

## Review basis

This review covered the requested production files, their corresponding tests, the four named documents plus `README.md`, and the diffs for `0c0dbd5`, `2794e14`, `ac15c6c`, `fe4baf4`, and `b159af6`. The unmodified tree passed `go test ./...` and `go test -race ./...` (121 tests in six packages).

Severity is ranked as requested: **CRITICAL** means credible data loss or silent destructive overwrite; **HIGH** means a destructive bypass or serious correctness/operability failure; **MEDIUM** means a material modeling or resilience gap; **LOW** means localized maintainability or diagnostic debt.

“CONFIRMED” means the behavior is directly implemented or asserted in this repository. “SUSPECTED” means the conclusion depends on Forward server behavior or an external operational assumption not present in this repository.

---

## 1. Core model

### Verdict

#### CRITICAL — CONFIRMED: there is no single reconcile-and-apply model

The strongest shared core is `buildPlanForConfig` → `buildPlanWithOptions` → `runPlannedSync`, used by the standard NQE flow, `safe-sync`, webhook execution, and authoritative manifest sync (`internal/app/run.go:215-247`, `internal/app/run.go:250-373`, `internal/app/account_manifest.go:71-101`, `internal/webhook/server.go:167-193`). Even inside that family, intent changes through boolean configuration: missing accounts are preserved unless either `AuthoritativeInput` or `PruneMissing` changes the same inventory into a replacement set (`internal/app/run.go:48-76`, `internal/app/run.go:1063-1076`).

`ApplyPlan` and `ChangeExternalID` independently reimplement setup lookup, current-state parsing, validation, audit, concurrency checking, and PATCH behavior (`internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:67-251`). Direct AWS Organizations and manifest onboarding use a separate create-payload builder and POST path, and deliberately refuse to update an existing named setup (`internal/app/run.go:376-542`).

### Every binary path that can mutate a Forward AWS setup

| Path | Desired-state computation | Mutation | Semantics and agreement |
|---|---|---|---|
| Root `awssync --apply` | NQE rows through the shared planner; additive by default, replacement only with `--prune-missing` (`internal/app/run.go:1063-1076`) | Sequential full setup PATCH through `applyPlan` (`internal/app/run.go:851-863`) | Agrees with webhook and manifest on payload construction, External ID preservation, and re-enable semantics, but CLI preview is not digest-bound to final apply (`cmd/awssync/main.go:75-138`). |
| `safe-sync` | Preflight, dry-run `app.Run`, then a second `app.Run`; no prune flag is exposed (`cmd/awssync/main.go:193-240`) | Same sequential PATCH path (`internal/app/run.go:356-369`) | Additive membership, rejects any previewed removal, skips aggregate zero add/re-enable, and binds the final payload hash; these are CLI-only guarantees (`cmd/awssync/main.go:219-240`). |
| `webhook --apply --yes` | Event selects snapshot/network/setup, then calls ordinary `app.Run` (`internal/webhook/server.go:167-193`) | Same sequential PATCH path (`internal/app/run.go:356-369`) | Planner semantics agree with root flags, but there is no preflight or per-event confirm/hash gate; event scope replaces configured scope (`cmd/awssync/main.go:847-887`, `internal/webhook/server.go:167-180`). |
| `sync-accounts` | Reviewed manifest is converted back into raw NQE-shaped maps and marked authoritative (`internal/app/account_manifest.go:71-101`) | Same sequential PATCH path (`internal/app/run.go:356-369`) | Same payload builder, but omission is removal and candidate/org evidence checks are skipped for authoritative input (`internal/app/run.go:321-333`, `internal/app/run.go:1063-1076`). |
| `apply-plan --yes` | Trusts arbitrary JSON patch payload maps from disk; computes only an ID-membership diff against current (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:80-130`) | Its own sequential PATCH loop (`internal/app/apply_plan.go:141-147`) | Does not share desired-state validation or change classification. It can alter `enabled`, ARNs, External IDs, regions, and proxy metadata without those changes appearing as removals (`internal/api/client.go:98-105`, `internal/app/apply_plan.go:108-130`). |
| `external-id --apply` | Copies the current `assumeRoleInfos`, changes selected External IDs, and constructs its own payload (`internal/app/external_id.go:109-209`) | Direct PATCH (`internal/app/external_id.go:241-251`) | Preserves account membership and existing enabled values in the initially read copy, but bypasses common rollback, final re-read, guards, and plan-bound confirmation (`cmd/awssync/main.go:260-306`). |
| `discover-org --post` | Direct AWS Organizations discovery produces a create payload (`internal/awsorg/discover.go:75-107`, `internal/app/run.go:376-487`) | POST creates a new setup (`internal/app/run.go:476-487`) | It cannot reconcile an existing setup: an existing name is rejected, and zero discovered accounts are rejected (`internal/app/run.go:413-435`). |
| `onboard-accounts --post` | Reviewed manifest goes through the new-setup builder (`internal/app/account_manifest.go:62-68`, `internal/app/run.go:376-542`) | POST creates a new setup (`internal/app/run.go:476-487`) | It shares direct-onboarding semantics, not existing-setup reconciliation; the manifest loader requires a nonempty, unique, exact-12-digit list (`internal/app/account_manifest.go:21-59`). |

`configure-webhook` mutates Forward webhook configuration, not the AWS setup account list, while `status`, `wait`, and the monitor are read-only with respect to cloud setups (`cmd/awssync/main.go:907-1052`, `internal/monitor/monitor.go:25-100`).

### Semantic disagreements

- **HIGH — CONFIRMED:** The shared planner always emits `Enabled: true` for target accounts, so standard, safe, webhook, and manifest sync re-enable disabled entries; External ID rotation preserves their prior enabled flags, while `apply-plan` accepts either value (`internal/app/run.go:1244-1261`, `internal/app/run.go:1666-1672`, `internal/app/external_id.go:121-193`, `internal/app/apply_plan.go:58-79`).
- **HIGH — CONFIRMED:** “Missing” means preserve in default NQE mode, remove in prune mode, and remove in manifest mode; this is policy encoded through booleans rather than a distinct desired-state source contract (`internal/app/run.go:48-76`, `internal/app/run.go:1063-1076`).
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
| NQE prune through root CLI | Configured ID is absent from the NQE-derived target and `--prune-missing` is set (`internal/app/run.go:1063-1076`, `internal/app/run.go:1716-1735`) | Apply confirmation or `--yes`; `--allow-removals`; both aggregate and per-setup ceilings; candidate and org-evidence checks; GovCloud positive-evidence rule; pre-PATCH re-read (`cmd/awssync/main.go:75-138`, `internal/app/run.go:307-350`) | Zero account rows fail. Any nonzero partial set is accepted as inventory and can remove all omitted IDs within approved ceilings; explicit snapshots skip freshness (`internal/app/run.go:1097-1102`, `internal/app/run.go:754-775`). |
| NQE prune through webhook | Same planner, when webhook daemon was started with prune/removal flags (`cmd/awssync/main.go:866-887`, `internal/webhook/server.go:167-193`) | Same in-`runPlannedSync` removal/evidence/bounds checks; only startup `--yes`, no preflight or per-event approval (`internal/app/run.go:307-350`, `cmd/awssync/main.go:847-887`) | Zero rows fail; partial nonzero and old event snapshots can remove omitted IDs, and events are not required to be monotonic (`internal/app/run.go:1097-1102`, `internal/webhook/server.go:167-193`). |
| Authoritative manifest sync | Configured ID omitted from the reviewed manifest (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:1063-1076`) | Generic confirmation/`--yes`; `--allow-removals`; both removal ceilings; pre-PATCH re-read. Candidate, org-evidence, and GovCloud NQE evidence checks are bypassed because the source is marked authoritative (`cmd/awssync/main.go:780-845`, `internal/app/run.go:307-350`) | Empty manifests and invalid/duplicate IDs fail before planning; a nonempty incomplete human-generated manifest is accepted as complete and removes omissions within bounds (`internal/app/account_manifest.go:21-59`). |
| `apply-plan` target omission | An account ID present in current state is missing from an arbitrary reviewed payload (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-114`) | `--yes`; `--allow-removals`; both ceilings; GovCloud removal always blocked; rollback file and pre-PATCH re-read (`cmd/awssync/main.go:488-536`, `internal/app/apply_plan.go:118-147`) | An empty `assumeRoleInfos` array is structurally accepted and can remove all commercial accounts if the explicit ceilings permit; there is no source evidence or completeness check (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:108-130`). |
| `apply-plan` disable | Account ID remains present but its `enabled` field is false (`internal/api/client.go:89-105`) | `--yes` only; removal diff and ceilings see no removed ID (`cmd/awssync/main.go:488-536`, `internal/app/apply_plan.go:108-130`) | Independent of inventory. A payload can disable every account without removal authorization (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:118-130`). |
| Stale read/modify/write overwrite | A concurrent actor adds/removes/edits accounts after the tool’s comparison read but before full-list PATCH (`internal/app/run.go:337-356`, `internal/app/apply_plan.go:141-147`, `internal/app/external_id.go:109-123`) | Main and `apply-plan` perform one non-atomic equality re-read; External ID performs none; no path sends a revision precondition (`internal/app/run.go:1851-1870`, `internal/api/client.go:355-363`, `internal/api/client.go:432-440`) | Not inventory-dependent. A newly added concurrent account absent from the stale target can be silently removed if the server replaces the array. |

No code path intentionally deletes the Forward setup object itself; setup mutations are POST for creation and PATCH for replacement/update (`internal/api/client.go:355-368`).

### Empty and truncated inventory

#### CRITICAL — CONFIRMED: empty is blocked, incomplete nonempty is not

The planner rejects a result from which no setup/account group can be formed with `no AWS accounts found in query response`, and preflight separately marks an empty NQE result failed (`internal/app/run.go:1084-1102`, `internal/app/preflight.go:78-88`). Direct AWS Organizations discovery propagates paginator errors instead of returning the partial list, and existing-setup onboarding rejects an empty discovered account list before POST (`internal/awsorg/discover.go:84-107`, `internal/app/run.go:413-416`).

The NQE client, however, treats a short page as conclusive end-of-data and exposes no total or completeness metadata to the planner (`internal/api/client.go:242-277`). Once at least one valid account row is present, pruning computes removals as every current ID missing from that set (`internal/app/run.go:1129-1136`, `internal/app/run.go:1716-1735`). Candidate/OU evidence proves only that at least one evidence-shaped row was visible, not that all organization pages or accounts were returned (`internal/app/run.go:1427-1455`).

Therefore:

- **CONFIRMED:** zero NQE accounts cannot directly mean “delete everything” in root, safe, webhook, or manifest planning (`internal/app/run.go:1097-1102`, `internal/app/account_manifest.go:38-40`).
- **CONFIRMED:** `apply-plan` can directly express an empty target list, subject only to explicit removal authorization and bounds for commercial setups (`internal/app/apply_plan.go:58-79`, `internal/app/apply_plan.go:118-130`).
- **CONFIRMED:** a truncated NQE response containing one surviving account can mean “delete every other account” under `--prune-missing --allow-removals` with sufficiently large count and percentage limits (`internal/api/client.go:227-277`, `internal/app/run.go:307-333`).
- **CONFIRMED:** default and safe-sync additive modes preserve missing current accounts, so truncated inventory cannot remove membership in those modes; they can still re-enable retained disabled accounts (`internal/app/run.go:1063-1076`, `internal/app/run.go:1228-1261`).

### Absence versus explicit deprovisioning

#### CRITICAL — CONFIRMED: the distinction does not exist

NQE account rows are reduced to setup ID, account ID, account name, collected flag, candidate/OU evidence, and raw string keys; there is no lifecycle state, source organization identity, tombstone, or completeness field (`internal/app/run.go:20-39`, `internal/app/run.go:1263-1409`). A manifest entry has only ID and optional name (`internal/app/account_manifest.go:16-19`). Consequently, prune and authoritative-manifest semantics infer removal solely from set absence (`internal/app/run.go:1063-1076`, `internal/app/run.go:1716-1735`).

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

Main planned sync and `apply-plan` capture rollback state and immediately re-GET to compare selected setup payloads using `reflect.DeepEqual` (`internal/app/run.go:337-350`, `internal/app/run.go:1851-1870`, `internal/app/apply_plan.go:132-143`). This detects a change before that GET completes, but cannot protect the interval from the successful GET to the subsequent PATCH (`internal/app/run.go:349-356`, `internal/app/apply_plan.go:141-147`). External ID rotation does not perform even that second read (`internal/app/external_id.go:109-123`, `internal/app/external_id.go:241-251`).

### Idempotency, retries, and partial failure

- **HIGH — CONFIRMED:** Reapplying an identical complete target is logically idempotent if no concurrent writer exists, because each retry sends the same serialized body; no application-level idempotency key makes that guarantee explicit (`internal/api/client.go:416-450`).
- **HIGH — CONFIRMED:** PATCH is classified as retryable on transport errors and 429/502/503/504 responses; if the server committed but the response was lost, the client sends the same body again without a revision or operation key (`internal/api/client.go:402-450`, `internal/api/client.go:460-492`).
- **HIGH — CONFIRMED:** A multi-setup plan is not atomic. The executor sorts/iterates setups and returns at the first PATCH error, leaving earlier successes in place; `runPlannedSync` then returns `nil, error` rather than a partial result containing the applied setup IDs (`internal/app/run.go:851-863`, `internal/app/run.go:356-359`).
- **HIGH — CONFIRMED:** A rerun usually converges toward the target, but there is no durable checkpoint or automatic rollback; already-applied setups can be PATCHed again while failed/later setups are retried (`internal/app/run.go:851-863`).
- **MEDIUM — CONFIRMED:** Rollback artifacts are written before the main/apply-plan loops, but rollback is manual and itself uses the same non-transactional `apply-plan` path (`internal/app/run.go:337-350`, `internal/app/apply_plan.go:132-159`, `docs/aws-account-sync-procedure.md:600-608`).
- **HIGH — CONFIRMED:** External ID mutation writes an `.applied` audit artifact but no pre-change rollback artifact, despite changing the full account array (`internal/app/external_id.go:205-251`).

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
- **CRITICAL — CONFIRMED — partial nonempty inventory:** there is no total/completeness proof, so prune interprets omissions as removals (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
- **MEDIUM — CONFIRMED — pagination pathologies:** the client has no repeated-page/cursor guard or advertised total; an API that repeats a full page loops indefinitely, and an API that silently caps below 1000 produces a false complete result (`internal/api/client.go:19`, `internal/api/client.go:242-277`).
- **LOW — CONFIRMED — direct AWS pagination errors:** Organizations discovery safely returns an error on any account or parent page failure rather than applying its accumulated prefix, but no test covers a later-page failure (`internal/awsorg/discover.go:84-107`, `internal/awsorg/discover.go:148-164`, `internal/awsorg/discover_test.go:49-96`).

### Identity, duplication, and movement

- **HIGH — CONFIRMED — account moved between organizations/setups:** the desired row contains no source organization identity or move operation; each setup is patched independently, so a move across two selected setups can partially complete and leave the account in both or neither (`internal/app/run.go:20-39`, `internal/app/run.go:1104-1201`, `internal/app/run.go:851-863`).
- **MEDIUM — CONFIRMED — duplicate discovered IDs:** deduplication silently keeps the first name/value and discards later conflicts; duplicates crossing NQE pages receive the same treatment (`internal/app/run.go:1457-1472`, `internal/api/client.go:242-277`).
- **MEDIUM — CONFIRMED — duplicate configured IDs:** `currentAccounts` deduplicates by ID for the diff, while External ID preservation later rejects duplicate current entries; behavior depends on which writer is used (`internal/app/run.go:1611-1628`, `internal/app/run.go:1689-1706`).
- **MEDIUM — CONFIRMED — duplicate setup names:** `SetupID` is derived from setup name (`internal/app/run.go:1481`) and the route key in the Forward API is `accountName` (`~/src/fwd/web/src/main/java/com/forwardnetworks/cv/web/controller/CloudAccountController.java:196-204`), so a later same-name setup overwrites the earlier one as a targeting collision (`internal/app/run.go:1474-1491`).
- **MEDIUM — CHANGED (Phase 1):** account IDs are now validated to exactly 12 digits across shared adapters (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/external_id.go:142-153`). This is a fail-closed change: malformed rows fail with operator-visible errors like `invalid AWS account ID "setup-a"; expected exactly 12 digits`, and a single malformed row can block a full sync on a large setup (`internal/app/run_test.go:748`).
- **MEDIUM — CONFIRMED — type/case/whitespace mismatch:** raw row extraction requires exact column keys and string values; numeric JSON IDs become empty, alternate key case is ignored, and setup matching is exact inside the planner even though interactive CLI selection canonicalizes case (`internal/app/run.go:1263-1289`, `internal/app/run.go:1412-1425`, `cmd/awssync/main.go:1685-1724`).
- **MEDIUM — CONFIRMED — ID versus ARN mismatch:** configured identity prefers `accountId` and otherwise parses the ARN; it does not assert that both values agree when both are present (`internal/app/external_id.go:254-259`, `internal/app/run.go:1708-1714`).
- **MEDIUM — CONFIRMED — name-only drift:** account diffing is ID-only, although the emitted target contains the newly discovered name; standard mode PATCHes that payload, while safe-sync classifies zero additions/re-enables as no change and exits before applying the name update (`internal/app/run.go:1666-1672`, `internal/app/run.go:1716-1743`, `cmd/awssync/main.go:223-227`).

### Lifecycle and state

- **HIGH — CONFIRMED — suspended/closed accounts:** NQE planning has no lifecycle field and cannot distinguish suspension from query absence; direct AWS onboarding either omits non-active accounts or, with `includeSuspended`, creates them as ordinary enabled target entries (`internal/app/run.go:20-39`, `internal/awsorg/discover.go:84-107`, `internal/app/run.go:645-657`).
- **MEDIUM — CONFIRMED — disabled accounts absent from additive inventory:** because current entries are merged into the target and every emitted target is enabled, an additive run re-enables disabled accounts even when NQE did not return them (`internal/app/run.go:1228-1261`, `internal/app/run.go:1666-1672`).
- **MEDIUM — CONFIRMED — explicit disable intent:** only raw `apply-plan` can preserve or introduce `enabled:false` as desired state; the normal planner has no typed disable transition (`internal/app/apply_plan.go:58-79`, `internal/app/run.go:1666-1672`).

### External ID drift and rotation

- **HIGH — CONFIRMED:** External ID rotation changes Forward first/only; there is no verification that the matching AWS role trust policy already accepts the value and no coordinated two-phase rotation (`internal/app/external_id.go:161-251`).
- **HIGH — CONFIRMED:** the External ID command has no rollback artifact or concurrent-update recheck, and its CLI confirmation occurs before the target payload/change list is computed (`cmd/awssync/main.go:275-301`, `internal/app/external_id.go:109-251`).
- **MEDIUM — CONFIRMED:** standard sync can also change External IDs from a CSV while its main diff reports membership/re-enable state rather than a typed per-account credential change, weakening review visibility (`internal/app/run.go:1137-1158`, `internal/app/run.go:1173-1201`).
- **MEDIUM — CONFIRMED:** mixed-ID setups require explicit assignments for new accounts, which safely fails closed, but there is no drift comparison to AWS or planned rotation window (`internal/app/run.go:1611-1664`).

### Ordering, time, and monitor/webhook behavior

- **HIGH — CONFIRMED — out-of-order webhook:** the worker is FIFO by arrival, not snapshot chronology, and accepts event-selected snapshot IDs without a last-applied watermark (`internal/webhook/server.go:167-215`).
- **HIGH — CONFIRMED — event loss:** `seenBefore` runs before the nonblocking queue send and before `app.Run`; queue-full and processing-failure retries remain marked seen for 24 hours (`internal/webhook/server.go:139-148`, `internal/webhook/server.go:180-215`).
- **MEDIUM — CONFIRMED — event duplicate identity:** an event ID, when present, is the entire dedupe key rather than network/snapshot/setup scope; restart loses all dedupe memory (`internal/webhook/server.go:195-215`).
- **HIGH — CONFIRMED — webhook scope expansion:** event network and setup IDs overwrite configured values; the server does not intersect them with an allowlist, and authorization succeeds unconditionally if configured username and password are both empty (`internal/webhook/server.go:152-180`).
- **MEDIUM — CONFIRMED — snapshot age:** an explicit snapshot bypasses the age check, and future-dated latest snapshots are not rejected because validation only checks whether age exceeds the maximum (`internal/app/run.go:754-775`).
- **MEDIUM — CONFIRMED — payload clock:** region `TestInstant == 0` becomes the current millisecond, so an otherwise identical preview and apply can hash differently (`internal/app/run.go:1765-1781`).
- **LOW — CONFIRMED — filename ordering:** default artifact names use second-level timestamps, so multiple runs in one second can address the same filename and the later atomic rename can replace the earlier artifact (`internal/app/run.go:739-751`, `internal/app/run.go:1872-1970`).
- **MEDIUM — CONFIRMED — monitor consistency:** `Status` fetches latest and the list in separate requests; `Wait` compares states case-sensitively, recognizes only `FAILED` and `ARCHIVED` as terminal, and polls forever for an absent snapshot until context cancellation (`internal/monitor/monitor.go:25-51`, `internal/monitor/monitor.go:54-100`).

---

## 5. Guard placement

### Guard matrix

| Guard | Root NQE | `safe-sync` | Webhook | Manifest sync | `apply-plan` | External ID |
|---|---:|---:|---:|---:|---:|---:|
| Typed desired-state validation | Partial/raw maps (`internal/app/run.go:1079-1207`) | Same | Same | Same after raw-map conversion (`internal/app/account_manifest.go:92-101`) | No; arbitrary JSON map (`internal/app/apply_plan.go:58-79`) | Separate validation (`internal/app/external_id.go:67-209`) |
| Preflight required | No (`cmd/awssync/main.go:59-138`) | Yes (`cmd/awssync/main.go:205-211`) | No (`internal/webhook/server.go:167-193`) | No (`cmd/awssync/main.go:780-845`) | No (`cmd/awssync/main.go:488-536`) | No (`cmd/awssync/main.go:260-306`) |
| Confirmation bound to payload hash | No (`cmd/awssync/main.go:75-138`) | Yes (`cmd/awssync/main.go:213-240`) | No | No | File itself is reviewed, but no baseline/revision binding (`internal/app/apply_plan.go:58-87`) | No |
| Removal authorization and ceilings | Yes (`internal/app/run.go:307-320`) | Removal invariant instead (`cmd/awssync/main.go:219-220`) | Yes if removals occur | Yes if removals occur | ID omissions only (`internal/app/apply_plan.go:108-130`) | Not applicable to intended field change |
| Candidate/org evidence | Yes for removals (`internal/app/run.go:321-333`) | No removals | Yes for removals | Bypassed as authoritative (`internal/app/run.go:321-333`) | No source evidence (`internal/app/apply_plan.go:108-130`) | No |
| Rollback artifact | Yes (`internal/app/run.go:337-348`) | Yes through same path | Yes through same path | Yes through same path | Yes (`internal/app/apply_plan.go:132-140`) | No (`internal/app/external_id.go:241-251`) |
| Last-moment equality re-read | Yes (`internal/app/run.go:349-350`) | Yes | Yes | Yes | Yes (`internal/app/apply_plan.go:141-143`) | No |
| Atomic CAS/version | No (`internal/api/client.go:355-363`) | No | No | No | No | No |
| Zero-diff PATCH suppression | No at executor (`internal/app/run.go:851-863`) | CLI add/re-enable only (`cmd/awssync/main.go:223-227`) | No | No | No (`internal/app/apply_plan.go:144-147`) | Yes for External ID field (`internal/app/external_id.go:241-242`) |
| Durable partial-apply result | No (`internal/app/run.go:356-359`) | No | No | No | No (`internal/app/apply_plan.go:144-159`) | Single setup |

### Bypasses

1. **HIGH — CONFIRMED:** `apply-plan` bypasses the main planner, candidate/org evidence, authoritative-source rules, and field-level change classification; `enabled:false` is not a removal (`internal/app/apply_plan.go:41-159`).
2. **HIGH — CONFIRMED:** External ID apply bypasses common rollback, final equality re-read, digest-bound preview, and removal/preflight policy (`cmd/awssync/main.go:260-306`, `internal/app/external_id.go:67-251`).
3. **HIGH — CONFIRMED:** webhook bypasses preflight and per-run confirmation; `--yes` is required only when the server is launched with apply enabled (`cmd/awssync/main.go:847-887`, `internal/webhook/server.go:167-193`).
4. **HIGH — CONFIRMED:** webhook request data bypasses the CLI’s case-insensitive setup resolution and can replace configured network/setup scope (`cmd/awssync/main.go:1685-1724`, `internal/webhook/server.go:167-180`).
5. **HIGH — CONFIRMED:** `sync-accounts` bypasses candidate and organization evidence by asserting a human manifest is authoritative; omission remains destructive (`internal/app/account_manifest.go:71-101`, `internal/app/run.go:321-333`).
6. **HIGH — CONFIRMED:** noninteractive root/CI with `--yes` bypasses confirmation and does not require preflight; safety then depends only on in-planner guards and supplied flags (`cmd/awssync/main.go:108-138`, `cmd/awssync/main.go:379-403`).
7. **HIGH — CONFIRMED:** standard interactive confirmation is bypassable by recomputation drift because the reviewed SHA is not copied into the apply config; safe-sync is the only mode that does so (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:237-240`).
8. **MEDIUM — CONFIRMED:** explicit snapshot IDs bypass `MaxSnapshotAge`, including webhook event snapshots (`internal/app/run.go:754-775`, `internal/webhook/server.go:167-180`).
9. **MEDIUM — CONFIRMED:** zero-change suppression can be bypassed by every shared-planner caller except the safe-sync wrapper; the executor contains no no-op check (`cmd/awssync/main.go:223-227`, `internal/app/run.go:851-863`).
10. **MEDIUM — CONFIRMED:** a positive candidate or OU count bypasses the no-evidence block without proving inventory completeness (`internal/app/run.go:1427-1455`).

The removal ceiling helper itself is shared, but the decision to invoke it is repeated at mutation call sites, so it is not a true chokepoint (`internal/app/removal_limits.go:14-93`, `internal/app/run.go:307-320`, `internal/app/preflight.go:138-150`, `internal/app/apply_plan.go:118-130`).

---

## 6. Test coverage

### What is covered well enough to be meaningful

- **CONFIRMED:** Main planner tests exercise destructive membership diffs, additive preservation, pruning, and malformed IDs (`internal/app/run_test.go:592-750`).
- **CONFIRMED:** Apply tests cover rollback output, reviewed-payload hash mismatch, removal opt-in, both blast-radius dimensions, no-candidate/no-org-evidence overrides, and GovCloud hard blocking (`internal/app/run_test.go:389-433`, `internal/app/run_test.go:752-863`, `internal/app/run_test.go:931-1302`).
- **CONFIRMED:** `apply-plan` tests cover GovCloud rejection, percentage/count bounds, and a setup change observed by the second GET before PATCH (`internal/app/apply_plan_test.go:72-251`).
- **CONFIRMED:** safe-sync tests cover preflight/preview/apply, multiple setups, noninteractive confirmation, zero-change skip, and failed preflight (`cmd/awssync/main_test.go:143-419`).
- **CONFIRMED:** External ID tests cover set/clear, selected-account scoping, CSV actions, preservation of other entries, and unsafe input rows (`internal/app/external_id_test.go:16-229`).
- **CONFIRMED:** API tests cover normal pagination, setup filtering, selected retries, and non-retry of create (`internal/api/client_test.go:13-155`, `internal/api/client_test.go:253-364`).

The suite is therefore not “mostly happy paths.” It verifies many of the reactive safeguards. Its weakness is that it tests each safeguard in the path where it was added, not the system-level invariants across every writer.

### Highest-value missing tests, in priority order

1. **CRITICAL — final GET/PATCH race:** block the PATCH after the equality re-read, inject a concurrent Forward edit, then assert the operation conflicts rather than clobbers; repeat for main, `apply-plan`, and External ID (`internal/app/run.go:349-356`, `internal/app/apply_plan_test.go:209-251`, `internal/app/external_id.go:241-251`).
2. **CRITICAL — incomplete nonempty NQE:** return one account from a larger current setup, including a short first page and a truncated later page, and assert destructive planning fails for lack of completeness rather than merely respecting broad ceilings (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
3. **HIGH — partial multi-setup apply:** make PATCH N fail after earlier successes, assert the returned result names applied/pending setups, and test safe resume/rollback and rerun behavior (`internal/app/run.go:851-863`, `internal/app/run.go:356-359`).
4. **HIGH — disable bypass:** feed `apply-plan` a same-membership payload with every `enabled:false` and assert destructive authorization is required (`internal/app/apply_plan.go:108-130`).
5. **HIGH — ambiguous PATCH retry:** simulate server commit followed by connection loss, concurrent edit before retry, and verify an idempotency/revision contract prevents overwrite (`internal/api/client.go:402-450`).
6. **HIGH — webhook delivery semantics:** cover queue-full after dedupe insertion, `app.Run` failure followed by redelivery, restart, event-ID collision, old-after-new snapshots, and an event trying to expand network/setup scope (`internal/webhook/server.go:139-215`, `internal/webhook/server_test.go:18-185`).
7. **HIGH — cross-setup move:** plan an account moving from setup A to B, fail either PATCH order, and assert an explicit move invariant prevents duplicate or missing final ownership (`internal/app/run.go:1104-1201`, `internal/app/run.go:851-863`).
8. **HIGH — External ID concurrency and recovery:** change account membership between initial GET and External ID PATCH and require conflict plus a verified rollback artifact (`internal/app/external_id.go:109-251`, `internal/app/external_id_test.go:16-229`).
9. **MEDIUM — account identity property/fuzz tests:** exact 12 digits, whitespace, numeric JSON types, conflicting duplicate rows across pages, `accountId`/ARN disagreement, and duplicate setup names (`internal/app/run.go:1263-1324`, `internal/app/run.go:1457-1491`, `internal/app/run.go:1708-1714`).
10. **MEDIUM — lifecycle tests:** active, suspended, closing, closed, moved, and unknown states must produce explicit typed decisions rather than absence-based pruning (`internal/awsorg/discover.go:130-146`, `internal/app/run.go:20-39`).
11. **MEDIUM — deterministic plan tests:** run preview/apply with zero `TestInstant`, name-only drift, and no account membership change; require stable digest and central no-op suppression (`internal/app/run.go:1765-1781`, `cmd/awssync/main.go:223-240`).
12. **MEDIUM — snapshot/monitor tests:** stale explicit snapshot, future timestamp, missing snapshot, lowercase/unknown terminal state, list pagination, and non-atomic latest/list changes (`internal/app/run.go:754-775`, `internal/monitor/monitor.go:25-100`, `internal/monitor/monitor_test.go:13-67`).
13. **MEDIUM — Organizations pagination tests:** multiple account pages, multiple parent pages, empty successful discovery, suspended inclusion, duplicate IDs, and a failure on page two (`internal/awsorg/discover.go:84-107`, `internal/awsorg/discover.go:148-164`, `internal/awsorg/discover_test.go:49-96`).
14. **MEDIUM — guard conformance table test:** run the same destructive `ChangeSet` through root, safe, webhook, manifest, apply-plan, and credential-update adapters and assert one central policy decision (`internal/app/run.go:307-350`, `internal/app/apply_plan.go:118-147`, `internal/app/external_id.go:241-251`).

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

This directly addresses the present split among raw-map planning, arbitrary plan application, and the External ID writer (`internal/app/run.go:1079-1207`, `internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:67-251`).

### Layer 1: typed domain model

Introduce types that cannot represent the current ambiguous states:

- `AccountID` validates exactly 12 digits once; `SetupID` has a canonical comparison form; `Partition` is an enum; `RoleARN` validates partition and asserts its account component matches `AccountID` (`internal/app/run.go:1313-1324`, `internal/app/account_manifest.go:14-50`, `internal/app/run.go:1708-1714`).
- `AccountLifecycle` is `Active | Suspended | Closing | Closed | Unknown`; `DesiredMembership` is `PresentEnabled | PresentDisabled | ExplicitlyRemove | Preserve`, so absence alone is not an action (`internal/awsorg/discover.go:130-146`, `internal/app/run.go:1063-1076`).
- `InventorySnapshot` includes source kind, network, snapshot ID/time, organization ID, selected setup scope, page/completeness proof, expected/observed counts, collection status, and lifecycle rows; the current NQE output lacks most of these fields (`internal/app/run.go:20-39`, `internal/api/client.go:227-277`).
- `CurrentSetup` includes a revision/ETag and preserves opaque server fields required for round-trip safety; current structs have neither (`internal/api/client.go:76-105`, `internal/api/client.go:355-363`).
- `ChangeSet` classifies `Add`, `Enable`, `Disable`, `Remove`, `Rename`, `RotateExternalID`, `ChangeRole`, and setup-metadata changes; current diffing is ID-only in `apply-plan` and membership/re-enable-only in the main planner (`internal/app/apply_plan.go:108-130`, `internal/app/run.go:1135-1158`).
- `ReconcilePolicy` is a tagged type such as `Additive`, `CompleteInventory`, or `ExplicitOperations`, replacing interacting booleans such as `PruneMissing`, `AuthoritativeInput`, and `AllowNoOrgEvidence` (`internal/app/run.go:48-76`).

Raw NQE maps and JSON/CSV files should exist only inside adapters. They must normalize or reject duplicate/conflicting IDs and exact column/type errors before reaching the domain planner (`internal/app/run.go:1263-1324`, `internal/app/run.go:1457-1472`).

### Layer 2: one desired-state and diff engine

`ComputeDesired` must be pure and deterministic: no API calls, file writes, or `time.Now`; its inputs include an explicit planning instant (`internal/app/run.go:1765-1781`). Every mutation mode should use it:

- NQE and manifests supply inventory adapters.
- `safe-sync` supplies `Additive` policy.
- root/webhook supply an explicitly selected policy.
- External ID rotation supplies explicit per-account credential operations against the same typed current state.
- `apply-plan` deserializes a versioned `ApplyIntent`, not an arbitrary patch map.

The engine should emit no payload when `ChangeSet` is empty, regardless of caller (`cmd/awssync/main.go:223-227`, `internal/app/run.go:851-863`). It should assert unique account ownership across all selected setups before permitting a cross-setup move (`internal/app/run.go:1104-1201`).

### Layer 3: one guard chokepoint

Every account-list PATCH must be impossible except through `GuardAndApply(intent, authorization)`. The gateway should enforce:

1. Exact account/ARN/partition uniqueness and consistency for current and target (`internal/app/run.go:1611-1664`, `internal/app/run.go:1708-1714`).
2. A complete, scope-matched inventory proof before any absence-based removal; otherwise only explicit tombstones can remove (`internal/api/client.go:227-277`, `internal/app/run.go:1129-1136`).
3. Typed destructive classification covering both `Remove` and `Disable`, not ID omission only (`internal/app/apply_plan.go:108-130`).
4. Aggregate/per-setup ceilings and explicit destructive authorization for all writers (`internal/app/removal_limits.go:24-80`).
5. GovCloud/source-specific evidence rules as policy, not CLI conditionals (`internal/app/run.go:321-333`).
6. Plan digest bound to baseline revision, source snapshot/completeness proof, policy, target payload, and approval identity; standard CLI currently binds none of these while safe-sync binds only payload bytes (`cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:237-240`).
7. Central zero-diff exit, rollback capture, audit, and redacted credential reporting (`internal/app/run.go:337-356`, `internal/app/external_id.go:241-251`).
8. CAS with `If-Match`/version. If the Forward API cannot provide CAS, treat account-list PATCH as unsafe for unattended destructive use; a last-second GET/hash is only a documented weak fallback (`internal/api/client.go:355-363`, `internal/app/run.go:1851-1870`).
9. An idempotency key for retryable writes, or no automatic retry after ambiguous transport failure (`internal/api/client.go:402-450`).
10. A durable result journal recording `planned`, `applied`, `conflicted`, `failed`, and `pending` per setup so partial multi-setup work can resume safely (`internal/app/run.go:851-863`).

Confirmation becomes a user-interface adapter that issues `ApplyAuthorization` for an immutable intent. `--yes` becomes a deliberate automation authorization record, not a way to bypass different prompt implementations (`cmd/awssync/main.go:108-138`, `cmd/awssync/main.go:499-518`).

### Layer 4: safe event processing

Webhook handling should persist an event before acknowledging it, mark dedupe only after durable admission, retry failed jobs with bounded backoff/dead-letter status, and key idempotency by network/snapshot/setup plus event ID (`internal/webhook/server.go:139-215`). It must intersect event scope with a configured allowlist, reject older-than-watermark snapshots per network/setup, and run the same immutable intent/gateway as CLI (`internal/webhook/server.go:167-193`).

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
8. Every mutation has a durable pre-state, post-state/digest, operation ID, and per-setup result; External ID currently violates the rollback part (`internal/app/external_id.go:241-251`).
9. A write conflict never silently retries against a newer baseline (`internal/api/client.go:402-450`).
10. A webhook cannot expand configured network/setup scope or move a setup backward to an older snapshot (`internal/webhook/server.go:167-215`).

### Phased refactor plan

| Phase | Work | Risk | Exit criterion |
|---|---|---|---|
| 0. Characterize destructive behavior | Add the missing race, partial inventory, disable, webhook, and partial-apply tests before behavior changes (`internal/app/apply_plan_test.go:209-251`, `internal/webhook/server_test.go:18-185`) | **LOW**: tests only, but some should intentionally expose failures | Each current mutation path has a guard-conformance and failure-injection test. |
| 1. Introduce domain types and adapters | Parse NQE, manifest, API, and External ID inputs into typed IDs/lifecycle/provenance; reject conflicts instead of first-wins (`internal/app/run.go:1263-1324`, `internal/app/run.go:1457-1472`) | **MEDIUM**: malformed inputs that previously slipped through will fail | No raw `map[string]any` crosses the adapter boundary; exact-ID and duplicate invariants are universal. |
| 2. Build pure desired-state/diff engine | Replace boolean-driven set merging with tagged policies and field-level `ChangeSet`; inject planning time (`internal/app/run.go:1063-1076`, `internal/app/run.go:1765-1781`) | **MEDIUM**: re-enable and name/metadata semantics become explicit and may change | Golden tests show identical intended additive/destructive payloads, with explicit differences documented. |
| 3. Create `GuardAndApply` gateway | Centralize no-op, destructive classification, evidence, ceilings, approval digest, rollback, audit, and progress journal; route main, manifest, `apply-plan`, and External ID through it (`internal/app/run.go:307-356`, `internal/app/apply_plan.go:41-159`, `internal/app/external_id.go:67-251`) | **HIGH**: mutation path changes; stage behind a compatibility flag and dry-run compare | Direct `PatchCloudAccount` calls exist only inside the gateway; conformance tests pass for every adapter. |
| 4. Add concurrency/idempotency contract | Forward has no client-visible revision token for `PatchCloudAccount`, so `If-Match` cannot be carried today; policy must prohibit unattended destructive writes until contract exists (`internal/api/client.go:355-363`, `internal/api/client.go:344-363`, `~/src/fwd/app/src/main/java/com/forwardnetworks/cv/sources/cloud/CloudAccountService.java:204-235`) | **HIGH / external dependency**: requires API contract change plus policy fallback | Concurrency tests should assert deterministic conflict replay and confirm gates for non-interactive destructive flows; header-based CAS is unavailable at the client boundary. |
| 5. Make multi-setup and webhook execution durable | Persist operation/event state, per-setup outcomes, retry/dead-letter, scope allowlists, and snapshot watermarks (`internal/app/run.go:851-863`, `internal/webhook/server.go:139-215`) | **MEDIUM-HIGH**: operational state and migration | Crash/restart and out-of-order tests show exactly-once intent with at-least-once delivery. |
| 6. Remove legacy paths and flags | Delete direct External ID/apply-plan writers, boolean combinations, and duplicate CLI safeguards after all callers use typed intents (`internal/app/run.go:48-76`, `cmd/awssync/main.go:373-403`) | **LOW-MEDIUM**: CLI compatibility | One planner, one guard gateway, one writer; deprecated flags map to explicit policy during a documented transition. |
| 7. Correct documentation and operating procedure | Align rollback, webhook auth/scope, completeness, CAS, and failure recovery claims with the implemented contract (`README.md:178-188`, `docs/aws-account-sync-procedure.md:438-458`) | **LOW** | No safety claim is broader than an enforced gateway invariant and its test. |

---

## Prioritized action list

1. **P0 / CRITICAL:** Disable destructive NQE pruning in unattended use until inventory completeness and org/setup identity can be proven; zero-row checks and candidate/OU heuristics are insufficient (`internal/api/client.go:227-277`, `internal/app/run.go:1427-1455`).
2. **P0 / CLOSED:** Full-list PATCH has no client-visible `ETag`/version/If-Match path; concurrent edits are replayed within server-side get-and-update semantics, so Phase 4 CAS is closed pending API changes, and policy must block unattended destructive full-list/account-update operations where idempotency cannot be proven (`internal/api/client.go:344-363`, `~/src/fwd/app/src/main/java/com/forwardnetworks/cv/sources/cloud/CloudAccountService.java:204-235`, `internal/app/external_id.go:241-251`).
3. **P0 / HIGH:** Close the `apply-plan` disable bypass by classifying `enabled:true→false` as destructive and routing it through the same authorization and budgets as removal (`internal/app/apply_plan.go:108-130`).
4. **P0 / HIGH:** Stop webhook scope replacement; require authentication for apply mode, intersect event scope with configured allowlists, persist events before acknowledgement, and reject older snapshots (`internal/webhook/server.go:139-215`).
5. **P1 / HIGH:** Add the six top failure-injection tests: final race window, incomplete nonempty inventory, partial multi-setup apply, disable bypass, ambiguous PATCH retry, and webhook loss/order (`internal/app/run.go:349-359`, `internal/api/client.go:227-277`, `internal/webhook/server.go:139-215`).
6. **P1 / HIGH:** Introduce typed `AccountID`, lifecycle, inventory provenance/completeness, desired membership, and field-level `ChangeSet`; reject duplicate/conflicting inputs (`internal/app/run.go:1263-1324`, `internal/app/run.go:1457-1472`).
7. **P1 / HIGH:** Build one immutable `ApplyIntent` and central `GuardAndApply` gateway; make direct PATCH calls outside it impossible (`internal/app/run.go:851-863`, `internal/app/apply_plan.go:144-147`, `internal/app/external_id.go:247-248`).
8. **P1 / HIGH:** Route External ID changes through that gateway with plan-bound review, rollback, CAS, and AWS trust-policy readiness verification (`cmd/awssync/main.go:260-306`, `internal/app/external_id.go:109-251`).
9. **P1 / HIGH:** Return and persist per-setup partial outcomes; provide explicit resume and rollback operations instead of returning an unqualified error after prior PATCH success (`internal/app/run.go:356-359`, `internal/app/run.go:851-863`).
10. **P2 / MEDIUM:** Make all planning deterministic, centralize zero-diff suppression, and bind every confirmation/automation approval to baseline revision + source evidence + policy + target digest (`internal/app/run.go:1765-1781`, `cmd/awssync/main.go:75-138`, `cmd/awssync/main.go:223-240`).
11. **P2 / MEDIUM:** Remove the single-setup overbroad fallback unless the source explicitly proves setup scope, and add pagination totals/repetition guards (`internal/api/client.go:227-318`, `internal/app/run.go:1326-1347`).
12. **P2 / MEDIUM:** Correct documentation immediately: External ID apply has no automatic rollback artifact, and webhook safety is conditional on launch flags, authentication, event scope, and source completeness (`README.md:178-188`, `internal/app/external_id.go:241-251`, `internal/webhook/server.go:152-193`).
