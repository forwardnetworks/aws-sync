package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestGuardAndApplyRejectsUnattendedDestructiveWithoutOverride(t *testing.T) {
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID: "setup-a",
		baseline: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
			gatewayAssumeRole("222222222222", true),
		},
		target:  []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)},
		changes: ChangeSet{Remove: []AccountChange{{AccountID: AccountID("222222222222")}}},
	}})
	result, err := GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest:                 intent.Digest(),
		Approved:                   true,
		AllowDestructive:           true,
		MaxRemovals:                1,
		MaxRemovalPercent:          100,
		AllowNoCandidates:          true,
		Unattended:                 true,
		AllowUnattendedDestructive: false,
	})
	const want = "refusing unattended destructive apply without --allow-unattended-destructive: plan removes or disables 1 account(s); Forward provides no atomic compare-and-swap"
	if err == nil || err.Error() != want {
		t.Fatalf("GuardAndApply() error = %v, want %q", err, want)
	}
	if !result.Blocked || result.PatchedCount != 0 {
		t.Fatalf("unexpected blocked result: %+v", result)
	}
}

func TestGuardAndApplyRequiresCompletenessForAbsenceBasedRemoval(t *testing.T) {
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID: "setup-a",
		baseline: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
			gatewayAssumeRole("222222222222", true),
		},
		target:  []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)},
		changes: ChangeSet{Remove: []AccountChange{{AccountID: AccountID("222222222222")}}},
	}})
	intent.state.snapshot.Completeness = InventoryCompletenessLikelyIncomplete
	intent.state.snapshot.CompletenessReason = "test snapshot is truncated"
	digest, err := computeApplyIntentDigest(intent.state)
	if err != nil {
		t.Fatal(err)
	}
	intent.state.digest = digest
	_, err = GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest:                 intent.Digest(),
		Approved:                   true,
		AllowDestructive:           true,
		MaxRemovals:                1,
		MaxRemovalPercent:          100,
		AllowNoCandidates:          true,
		AllowUnattendedDestructive: true,
	})
	if err == nil || !strings.Contains(err.Error(), "inventory completeness is unproven: test snapshot is truncated") {
		t.Fatalf("completeness error = %v", err)
	}
}

func TestGuardAndApplyRejectsNQEDerivedRemovalIntent(t *testing.T) {
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID: "setup-a",
		baseline: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
			gatewayAssumeRole("222222222222", true),
		},
		target:  []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)},
		changes: ChangeSet{Remove: []AccountChange{{AccountID: AccountID("222222222222")}}},
	}})
	intent.state.snapshot.Source = "nqe"
	digest, err := computeApplyIntentDigest(intent.state)
	if err != nil {
		t.Fatal(err)
	}
	intent.state.digest = digest

	_, err = GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest:                 intent.Digest(),
		Approved:                   true,
		AllowDestructive:           true,
		MaxRemovals:                1,
		MaxRemovalPercent:          100,
		AllowNoCandidates:          true,
		AllowUnattendedDestructive: true,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing CompleteInventory reconciliation for NQE observed inventory") {
		t.Fatalf("GuardAndApply() error = %v; want NQE removal refusal", err)
	}
}

func TestGuardAndApplyGovCloudRemovalUsesBaselinePartition(t *testing.T) {
	govAccount := gatewayAssumeRole("111111111111", true)
	govAccount.RoleArn = "arn:aws-us-gov:iam::111111111111:role/ForwardRole"
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID:  "setup-gov",
		baseline: []api.AssumeRoleInfo{govAccount},
		target:   nil,
		changes:  ChangeSet{Remove: []AccountChange{{AccountID: AccountID("111111111111")}}},
	}})
	intent.state.policy.OrganizationEvidence = AllowMissingOrganizationEvidence
	digest, err := computeApplyIntentDigest(intent.state)
	if err != nil {
		t.Fatal(err)
	}
	intent.state.digest = digest
	_, err = GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest:                 intent.Digest(),
		Approved:                   true,
		AllowDestructive:           true,
		MaxRemovals:                1,
		MaxRemovalPercent:          100,
		AllowNoCandidates:          true,
		AllowUnattendedDestructive: true,
	})
	if err == nil || !strings.Contains(err.Error(), "GovCloud account removals require positive AWS Organizations evidence") {
		t.Fatalf("GovCloud baseline partition error = %v", err)
	}
}

func TestGuardAndApplyDisableUsesDestructiveAuthorizationAndRemovalBudget(t *testing.T) {
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID: "setup-a",
		baseline: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
		},
		target: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", false),
		},
		changes: ChangeSet{Disable: []AccountChange{{AccountID: AccountID("111111111111")}}},
	}})
	_, err := GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest: intent.Digest(),
		Approved:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-removals") {
		t.Fatalf("disable without destructive authorization error = %v", err)
	}

	_, err = GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest:        intent.Digest(),
		Approved:          true,
		AllowDestructive:  true,
		MaxRemovals:       1,
		MaxRemovalPercent: 50,
		AllowNoCandidates: true,
	})
	if err == nil || !strings.Contains(err.Error(), "removes 1 of 1 accounts (100.00%)") {
		t.Fatalf("disable per-setup budget error = %v", err)
	}
}

func TestApplyIntentDigestBindsBaselineSnapshotPolicyAndTarget(t *testing.T) {
	setup := gatewayTestSetup{
		setupID: "setup-a",
		baseline: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
		},
		target: []api.AssumeRoleInfo{
			gatewayAssumeRole("111111111111", true),
			gatewayAssumeRole("222222222222", true),
		},
		changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("222222222222")}}},
	}
	base := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{setup})
	digests := map[string]string{"base": base.Digest()}

	baseline := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{setup})
	baseline.state.baselines["setup-a"] = clonePatchPayload(baseline.state.baselines["setup-a"])
	payload := baseline.state.baselines["setup-a"]
	payload.ProxyServerID = "changed-baseline"
	baseline.state.baselines["setup-a"] = payload
	baseline.state.setups[0].baseline = clonePatchPayload(payload)
	digests["baseline"], _ = computeApplyIntentDigest(baseline.state)

	snapshot := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{setup})
	snapshot.state.snapshot.SnapshotID = "different-snapshot"
	snapshot.state.snapshot.Completeness = InventoryCompletenessLikelyIncomplete
	digests["snapshot"], _ = computeApplyIntentDigest(snapshot.state)

	policy := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{setup})
	policy.state.policy.Kind = Additive
	digests["policy"], _ = computeApplyIntentDigest(policy.state)

	target := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{setup})
	payload = target.state.targets["setup-a"]
	payload.ProxyServerID = "changed-target"
	target.state.targets["setup-a"] = payload
	target.state.setups[0].target = clonePatchPayload(payload)
	digests["target"], _ = computeApplyIntentDigest(target.state)

	for name, digest := range digests {
		if name == "base" {
			continue
		}
		if digest == digests["base"] {
			t.Errorf("%s change did not alter apply intent digest %s", name, digest)
		}
	}
}

func TestApplyIntentDigestChangesWhenPlanMeaningfullyChanges(t *testing.T) {
	baseline := []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)}
	first := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID:  "setup-a",
		baseline: baseline,
		target: append(append([]api.AssumeRoleInfo(nil), baseline...),
			gatewayAssumeRole("222222222222", true)),
		changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("222222222222")}}},
	}})
	second := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{{
		setupID:  "setup-a",
		baseline: baseline,
		target: append(append([]api.AssumeRoleInfo(nil), baseline...),
			gatewayAssumeRole("333333333333", true)),
		changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("333333333333")}}},
	}})

	if first.Digest() == "" || second.Digest() == "" {
		t.Fatalf("meaningful plans produced empty digests: first=%q second=%q", first.Digest(), second.Digest())
	}
	if first.Digest() == second.Digest() {
		t.Fatalf("different target accounts produced the same digest %q", first.Digest())
	}
}

func TestApplyIntentDigestZeroValueIsEmpty(t *testing.T) {
	if got := (ApplyIntent{}).Digest(); got != "" {
		t.Fatalf("zero-value ApplyIntent digest = %q, want empty", got)
	}
}

func TestValidateDestructiveEvidence(t *testing.T) {
	type evidenceSetup struct {
		setupID        string
		baseline       api.AssumeRoleInfo
		changes        ChangeSet
		candidateCount int
		orgUnitCount   int
	}
	govAccount := gatewayAssumeRole("111111111111", true)
	govAccount.RoleArn = "arn:aws-us-gov:iam::111111111111:role/ForwardRole"
	remove := ChangeSet{Remove: []AccountChange{{AccountID: AccountID("111111111111")}}}
	disable := ChangeSet{Disable: []AccountChange{{AccountID: AccountID("111111111111")}}}
	tests := []struct {
		name              string
		evidence          OrganizationEvidencePolicy
		setups            []evidenceSetup
		allowNoCandidates bool
		wantError         string
	}{
		{
			name:     "reviewed authoritative inventory bypasses discovery evidence",
			evidence: ReviewedAuthoritativeInventory,
			setups:   []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: remove}},
		},
		{
			name:      "removal with no candidates requires override",
			evidence:  AllowMissingOrganizationEvidence,
			setups:    []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: remove}},
			wantError: "planned removals with no uncollected candidate accounts visible require --allow-no-candidates",
		},
		{
			name:      "disable with no candidates requires override",
			evidence:  AllowMissingOrganizationEvidence,
			setups:    []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: disable}},
			wantError: "planned removals or disables with no uncollected candidate accounts visible require --allow-no-candidates",
		},
		{
			name:              "GovCloud removal requires positive evidence",
			evidence:          AllowMissingOrganizationEvidence,
			setups:            []evidenceSetup{{setupID: "setup-gov", baseline: govAccount, changes: remove}},
			allowNoCandidates: true,
			wantError:         "GovCloud account removals require positive AWS Organizations evidence; use sync-accounts with an authoritative reviewed manifest when Organizations is unavailable",
		},
		{
			name:              "GovCloud disable requires positive evidence",
			evidence:          AllowMissingOrganizationEvidence,
			setups:            []evidenceSetup{{setupID: "setup-gov", baseline: govAccount, changes: disable}},
			allowNoCandidates: true,
			wantError:         "GovCloud account removals or disables require positive AWS Organizations evidence; use sync-accounts with an authoritative reviewed manifest when Organizations is unavailable",
		},
		{
			name:     "required evidence reports sorted removal setups",
			evidence: RequireOrganizationEvidence,
			setups: []evidenceSetup{
				{setupID: "setup-z", baseline: gatewayAssumeRole("111111111111", true), changes: remove},
				{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: remove},
			},
			allowNoCandidates: true,
			wantError:         "planned removals with no AWS Organizations evidence in NQE for setup(s): setup-a, setup-z require --allow-no-org-evidence",
		},
		{
			name:              "required evidence distinguishes disables",
			evidence:          RequireOrganizationEvidence,
			setups:            []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: disable}},
			allowNoCandidates: true,
			wantError:         "planned removals or disables with no AWS Organizations evidence in NQE for setup(s): setup-a require --allow-no-org-evidence",
		},
		{
			name:              "allow missing evidence accepts explicit override",
			evidence:          AllowMissingOrganizationEvidence,
			setups:            []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: remove}},
			allowNoCandidates: true,
		},
		{
			name:     "visible candidates satisfy required evidence",
			evidence: RequireOrganizationEvidence,
			setups: []evidenceSetup{{
				setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true), changes: remove, candidateCount: 1,
			}},
		},
		{
			name:     "non-destructive setup needs no evidence",
			evidence: RequireOrganizationEvidence,
			setups:   []evidenceSetup{{setupID: "setup-a", baseline: gatewayAssumeRole("111111111111", true)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatewaySetups := make([]gatewayTestSetup, 0, len(tt.setups))
			counts := make(map[string][2]int, len(tt.setups))
			for _, setup := range tt.setups {
				gatewaySetups = append(gatewaySetups, gatewayTestSetup{
					setupID:  setup.setupID,
					baseline: []api.AssumeRoleInfo{setup.baseline},
					changes:  setup.changes,
				})
				counts[setup.setupID] = [2]int{setup.candidateCount, setup.orgUnitCount}
			}
			intent := gatewayTestIntent(t, t.TempDir(), gatewaySetups)
			intent.state.policy.OrganizationEvidence = tt.evidence
			for index := range intent.state.setups {
				count := counts[intent.state.setups[index].setupID]
				intent.state.setups[index].discoveredCandidateCount = count[0]
				intent.state.setups[index].discoveredOrgUnitRowCount = count[1]
			}

			err := validateDestructiveEvidence(intent.state, ApplyAuthorization{AllowNoCandidates: tt.allowNoCandidates})
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateDestructiveEvidence() error = %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantError {
				t.Fatalf("validateDestructiveEvidence() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestGuardAndApplyPreApplyArtifactFailureFailsEveryPendingSetup(t *testing.T) {
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{
		{
			setupID:  "setup-a",
			baseline: []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)},
			target: []api.AssumeRoleInfo{
				gatewayAssumeRole("111111111111", true),
				gatewayAssumeRole("222222222222", true),
			},
			changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("222222222222")}}},
		},
		{
			setupID:  "setup-b",
			baseline: []api.AssumeRoleInfo{gatewayAssumeRole("333333333333", true)},
			target: []api.AssumeRoleInfo{
				gatewayAssumeRole("333333333333", true),
				gatewayAssumeRole("444444444444", true),
			},
			changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("444444444444")}}},
		},
	})
	if err := os.Mkdir(rollbackPath(intent.state.outputPath), 0o700); err != nil {
		t.Fatal(err)
	}

	result, err := GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest: intent.Digest(),
		Approved:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "write pre-apply rollback payload") {
		t.Fatalf("GuardAndApply() error = %v, want rollback artifact failure", err)
	}
	if result.PatchedCount != 0 {
		t.Fatalf("patched count = %d, want 0", result.PatchedCount)
	}
	for _, setupID := range []string{"setup-a", "setup-b"} {
		assertGatewayJournalEntry(t, result.Journal, setupID, ApplyStatusFailed,
			[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusFailed},
			"write pre-apply rollback payload")
	}

	persisted := readGatewayJournal(t, result.JournalOutput)
	for _, setupID := range []string{"setup-a", "setup-b"} {
		assertGatewayJournalEntry(t, persisted, setupID, ApplyStatusFailed,
			[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusFailed},
			"write pre-apply rollback payload")
	}
}

func TestGuardAndApplyReturnsDurablePartialJournal(t *testing.T) {
	var (
		mu    sync.Mutex
		state = map[string][]api.AssumeRoleInfo{
			"setup-a": {gatewayAssumeRole("111111111111", true)},
			"setup-b": {gatewayAssumeRole("222222222222", true)},
			"setup-c": {gatewayAssumeRole("333333333333", true)},
		}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			mu.Lock()
			accounts := []api.CloudAccount{
				{Name: "setup-a", Type: "AWS", AssumeRoleInfos: append([]api.AssumeRoleInfo(nil), state["setup-a"]...)},
				{Name: "setup-b", Type: "AWS", AssumeRoleInfos: append([]api.AssumeRoleInfo(nil), state["setup-b"]...)},
				{Name: "setup-c", Type: "AWS", AssumeRoleInfos: append([]api.AssumeRoleInfo(nil), state["setup-c"]...)},
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(accounts)
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/setup-b"):
			http.Error(w, "injected failure", http.StatusInternalServerError)
		case r.Method == http.MethodPatch:
			setupID := strings.TrimPrefix(r.URL.Path, "/api/networks/network-1/cloudAccounts/")
			var payload api.PatchPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			state[setupID] = append([]api.AssumeRoleInfo(nil), payload.AssumeRoleInfos...)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := api.NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	intent := gatewayTestIntent(t, t.TempDir(), []gatewayTestSetup{
		{
			setupID:  "setup-a",
			baseline: []api.AssumeRoleInfo{gatewayAssumeRole("111111111111", true)},
			target: []api.AssumeRoleInfo{
				gatewayAssumeRole("111111111111", true),
				gatewayAssumeRole("444444444444", true),
			},
			changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("444444444444")}}},
		},
		{
			setupID:  "setup-b",
			baseline: []api.AssumeRoleInfo{gatewayAssumeRole("222222222222", true)},
			target: []api.AssumeRoleInfo{
				gatewayAssumeRole("222222222222", true),
				gatewayAssumeRole("555555555555", true),
			},
			changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("555555555555")}}},
		},
		{
			setupID:  "setup-c",
			baseline: []api.AssumeRoleInfo{gatewayAssumeRole("333333333333", true)},
			target: []api.AssumeRoleInfo{
				gatewayAssumeRole("333333333333", true),
				gatewayAssumeRole("666666666666", true),
			},
			changes: ChangeSet{Add: []AccountChange{{AccountID: AccountID("666666666666")}}},
		},
	})
	result, err := GuardAndApply(context.Background(), client, intent, ApplyAuthorization{
		PlanDigest: intent.Digest(),
		Approved:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "setup-b") {
		t.Fatalf("GuardAndApply() error = %v, want setup-b failure", err)
	}
	if result.PatchedCount != 1 {
		t.Fatalf("patched count = %d, want 1", result.PatchedCount)
	}
	assertGatewayJournalEntry(t, result.Journal, "setup-a", ApplyStatusApplied,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusApplied}, "")
	assertGatewayJournalEntry(t, result.Journal, "setup-b", ApplyStatusFailed,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusFailed}, "patch setup setup-b")
	assertGatewayJournalEntry(t, result.Journal, "setup-c", ApplyStatusPending,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending}, "")

	persisted := readGatewayJournal(t, result.JournalOutput)
	if len(persisted.Setups) != 3 {
		t.Fatalf("persisted journal = %#v", persisted)
	}
	assertGatewayJournalEntry(t, persisted, "setup-a", ApplyStatusApplied,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusApplied}, "")
	assertGatewayJournalEntry(t, persisted, "setup-b", ApplyStatusFailed,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending, ApplyStatusFailed}, "patch setup setup-b")
	assertGatewayJournalEntry(t, persisted, "setup-c", ApplyStatusPending,
		[]ApplyStatus{ApplyStatusPlanned, ApplyStatusPending}, "")
}

func readGatewayJournal(t *testing.T, path string) ApplyJournal {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read durable journal: %v", err)
	}
	var journal ApplyJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatalf("decode durable journal: %v", err)
	}
	return journal
}

func assertGatewayJournalEntry(
	t *testing.T,
	journal ApplyJournal,
	setupID string,
	wantStatus ApplyStatus,
	wantHistory []ApplyStatus,
	wantError string,
) {
	t.Helper()
	entry := journalEntry(&journal, setupID)
	if entry == nil {
		t.Fatalf("journal has no entry for %s: %#v", setupID, journal.Setups)
	}
	if entry.Status != wantStatus {
		t.Fatalf("journal status for %s = %q, want %q", setupID, entry.Status, wantStatus)
	}
	if len(entry.History) != len(wantHistory) {
		t.Fatalf("journal history for %s = %#v, want %#v", setupID, entry.History, wantHistory)
	}
	for index := range wantHistory {
		if entry.History[index] != wantHistory[index] {
			t.Fatalf("journal history for %s = %#v, want %#v", setupID, entry.History, wantHistory)
		}
	}
	if wantError == "" {
		if entry.Error != "" {
			t.Fatalf("journal error for %s = %q, want empty", setupID, entry.Error)
		}
		return
	}
	if !strings.Contains(entry.Error, wantError) {
		t.Fatalf("journal error for %s = %q, want substring %q", setupID, entry.Error, wantError)
	}
}

type gatewayTestSetup struct {
	setupID  string
	baseline []api.AssumeRoleInfo
	target   []api.AssumeRoleInfo
	changes  ChangeSet
}

func gatewayTestIntent(t *testing.T, dir string, setups []gatewayTestSetup) ApplyIntent {
	t.Helper()
	state := &applyIntentState{
		networkID:  "network-1",
		outputPath: filepath.Join(dir, "payload.json"),
		snapshot: InventorySnapshot{
			Source:       "test",
			NetworkID:    "network-1",
			Completeness: InventoryCompletenessComplete,
		},
		policy: ReconcilePolicy{
			Kind:                 CompleteInventory,
			PlanningInstant:      time.Unix(1, 0).UTC(),
			OrganizationEvidence: ReviewedAuthoritativeInventory,
		},
		baselines: make(auditPayloads),
		targets:   make(auditPayloads),
	}
	for _, setup := range setups {
		baseline := api.PatchPayload{
			Type:                  "AWS",
			Name:                  setup.setupID,
			Regions:               map[string]int64{},
			RegionToProxyServerID: map[string]string{},
			AssumeRoleInfos:       setup.baseline,
		}
		target := api.PatchPayload{
			Type:                  "AWS",
			Name:                  setup.setupID,
			Regions:               map[string]int64{},
			RegionToProxyServerID: map[string]string{},
			AssumeRoleInfos:       setup.target,
		}
		state.baselines[setup.setupID] = clonePatchPayload(baseline)
		state.targets[setup.setupID] = clonePatchPayload(target)
		state.setups = append(state.setups, applySetupIntent{
			setupID:  setup.setupID,
			baseline: clonePatchPayload(baseline),
			target:   clonePatchPayload(target),
			changes:  cloneChangeSet(setup.changes),
		})
	}
	sort.Slice(state.setups, func(i, j int) bool {
		return state.setups[i].setupID < state.setups[j].setupID
	})
	digest, err := computeApplyIntentDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	state.digest = digest
	return ApplyIntent{state: state}
}

func gatewayAssumeRole(accountID string, enabled bool) api.AssumeRoleInfo {
	return api.AssumeRoleInfo{
		AccountID: accountID,
		RoleArn:   "arn:aws:iam::" + accountID + ":role/ForwardRole",
		Enabled:   enabled,
	}
}
