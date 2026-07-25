package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestComputeDesiredIsDeterministicAndClassifiesFieldChanges(t *testing.T) {
	planningInstant := time.Date(2026, time.July, 25, 12, 34, 56, 0, time.UTC)
	current := CurrentSetup{
		SetupID: SetupID("setup-a"),
		Metadata: SetupMetadata{
			CloudType:           "AWS",
			ProxyServerID:       "proxy-a",
			RegionToProxyServer: map[string]string{"us-east-1": "proxy-a"},
			Regions:             map[string]int64{"us-east-1": 0},
		},
		Accounts: []SetupAccount{
			reconcileTestAccount(t, "111111111111", "old-name", "OldRole", "old-external", false),
			reconcileTestAccount(t, "333333333333", "remove-me", "OldRole", "old-external", true),
		},
	}
	snapshot := InventorySnapshot{
		Completeness: InventoryCompletenessComplete,
		DiscoveredAccounts: []DiscoveredAccount{
			{SetupID: SetupID("setup-a"), AccountID: AccountID("111111111111"), AccountName: "new-name"},
			{SetupID: SetupID("setup-a"), AccountID: AccountID("222222222222"), AccountName: "add-me"},
		},
	}
	uniformExternalID := "new-external"
	policy := ReconcilePolicy{
		Kind:              CompleteInventory,
		PlanningInstant:   planningInstant,
		DefaultRoleName:   "NewRole",
		UniformExternalID: &uniformExternalID,
	}

	firstDesired, firstChanges, err := ComputeDesired(current, snapshot, policy)
	if err != nil {
		t.Fatalf("ComputeDesired() error = %v", err)
	}
	secondDesired, secondChanges, err := ComputeDesired(current, snapshot, policy)
	if err != nil {
		t.Fatalf("second ComputeDesired() error = %v", err)
	}
	if !reflect.DeepEqual(firstDesired, secondDesired) || !reflect.DeepEqual(firstChanges, secondChanges) {
		t.Fatalf("identical inputs produced different output:\nfirst=%#v %#v\nsecond=%#v %#v", firstDesired, firstChanges, secondDesired, secondChanges)
	}
	if got := current.Metadata.Regions["us-east-1"]; got != 0 {
		t.Fatalf("ComputeDesired mutated current regions: %d", got)
	}
	if got := firstDesired.Metadata.Regions["us-east-1"]; got != planningInstant.UnixMilli() {
		t.Fatalf("desired planning instant = %d, want %d", got, planningInstant.UnixMilli())
	}
	if len(firstChanges.Add) != 1 ||
		len(firstChanges.Enable) != 1 ||
		len(firstChanges.Remove) != 1 ||
		len(firstChanges.Rename) != 1 ||
		len(firstChanges.RotateExternalID) != 1 ||
		len(firstChanges.ChangeRole) != 1 ||
		len(firstChanges.SetupMetadata) != 1 {
		t.Fatalf("unexpected field-level changes: %#v", firstChanges)
	}
	if len(firstChanges.Disable) != 0 {
		t.Fatalf("unexpected disable changes: %#v", firstChanges.Disable)
	}
}

func TestComputeDesiredCompletenessInvariantByPolicy(t *testing.T) {
	current := CurrentSetup{
		SetupID: SetupID("setup-a"),
		Metadata: SetupMetadata{
			CloudType: "AWS",
		},
		Accounts: []SetupAccount{
			reconcileTestAccount(t, "111111111111", "keep", "ForwardRole", "", true),
			reconcileTestAccount(t, "222222222222", "missing", "ForwardRole", "", true),
		},
	}
	snapshot := InventorySnapshot{
		Completeness:       InventoryCompletenessLikelyIncomplete,
		CompletenessReason: "repeated page",
		ObservedRowCount:   api.PageLimit,
		PageLimit:          api.PageLimit,
		DiscoveredAccounts: []DiscoveredAccount{{
			SetupID: SetupID("setup-a"), AccountID: AccountID("111111111111"), AccountName: "keep",
		}},
	}
	base := ReconcilePolicy{
		PlanningInstant: time.Unix(123, 0).UTC(),
		DefaultRoleName: "ForwardRole",
	}

	complete := base
	complete.Kind = CompleteInventory
	if _, _, err := ComputeDesired(current, snapshot, complete); err == nil || !strings.Contains(err.Error(), "inventory completeness is unproven") {
		t.Fatalf("CompleteInventory error = %v; want completeness refusal", err)
	}

	additive := base
	additive.Kind = Additive
	desired, changes, err := ComputeDesired(current, snapshot, additive)
	if err != nil {
		t.Fatalf("Additive error = %v", err)
	}
	if len(desired.Accounts) != 2 || len(changes.Remove) != 0 {
		t.Fatalf("Additive removed missing accounts: desired=%#v changes=%#v", desired, changes)
	}
}

func TestComputeDesiredRejectsCompleteInventoryForNQESource(t *testing.T) {
	current := CurrentSetup{
		SetupID:  SetupID("setup-a"),
		Metadata: SetupMetadata{CloudType: "AWS"},
		Accounts: []SetupAccount{
			reconcileTestAccount(t, "111111111111", "keep", "ForwardRole", "", true),
			reconcileTestAccount(t, "222222222222", "would-be-removed", "ForwardRole", "", true),
		},
	}
	snapshot := InventorySnapshot{
		Source:       "nqe",
		Completeness: InventoryCompletenessComplete,
		DiscoveredAccounts: []DiscoveredAccount{{
			SetupID: SetupID("setup-a"), AccountID: AccountID("111111111111"), AccountName: "keep",
		}},
	}
	policy := NewAuthoritativeManifestReconcilePolicy(time.Unix(123, 0).UTC())

	_, _, err := ComputeDesired(current, snapshot, policy)
	if err == nil || !strings.Contains(err.Error(), "refusing CompleteInventory reconciliation for NQE observed inventory") {
		t.Fatalf("ComputeDesired() error = %v; want NQE CompleteInventory refusal", err)
	}
}

func TestReconcilePolicyConstructorsKeepNQEAdditiveAndManifestComplete(t *testing.T) {
	instant := time.Unix(123, 0).UTC()

	for _, allowNoOrg := range []bool{false, true} {
		policy := NewNQEReconcilePolicy(allowNoOrg, instant)
		wantEvidence := RequireOrganizationEvidence
		if allowNoOrg {
			wantEvidence = AllowMissingOrganizationEvidence
		}
		if policy.Kind != Additive || policy.OrganizationEvidence != wantEvidence || !policy.PlanningInstant.Equal(instant) {
			t.Fatalf("unexpected NQE policy: %#v", policy)
		}
	}

	manifest := NewAuthoritativeManifestReconcilePolicy(instant)
	if manifest.Kind != CompleteInventory || manifest.OrganizationEvidence != ReviewedAuthoritativeInventory || !manifest.PlanningInstant.Equal(instant) {
		t.Fatalf("unexpected manifest policy: %#v", manifest)
	}
}

func TestBuildPlanRejectsCrossSetupMoveUntilApplyIsAtomic(t *testing.T) {
	items := []map[string]any{
		{"Cloud Setup ID": "setup-b", "Cloud Account ID": "111111111111", "Cloud Account Name": "move-me"},
		{"Cloud Setup ID": "setup-b", "Cloud Account ID": "222222222222", "Cloud Account Name": "stay"},
	}
	cloudAccounts := []api.CloudAccount{
		{
			Type: "AWS",
			Name: "setup-a",
			AssumeRoleInfos: []api.AssumeRoleInfo{{
				AccountID: "111111111111", AccountName: "move-me", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole", Enabled: true,
			}},
		},
		{
			Type: "AWS",
			Name: "setup-b",
			AssumeRoleInfos: []api.AssumeRoleInfo{{
				AccountID: "222222222222", AccountName: "stay", RoleArn: "arn:aws:iam::222222222222:role/ForwardRole", Enabled: true,
			}},
		},
	}
	if _, err := buildPlan(items, cloudAccounts, "", nil); err == nil || !strings.Contains(err.Error(), "refusing cross-setup move") {
		t.Fatalf("buildPlan() error = %v; want non-atomic move refusal", err)
	}
}

func TestBuildPlanOmitsPayloadForEmptyChangeSet(t *testing.T) {
	items := []map[string]any{{
		"Cloud Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "account-a",
	}}
	cloudAccounts := []api.CloudAccount{{
		Type: "AWS",
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{{
			AccountID: "111111111111", AccountName: "account-a", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole", Enabled: true,
		}},
	}}
	plan, err := buildPlan(items, cloudAccounts, "", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if len(plan.Setups) != 1 || !plan.Setups[0].ChangeSet.Empty() {
		t.Fatalf("unexpected no-op plan: %#v", plan)
	}
	if len(plan.Payloads) != 0 {
		t.Fatalf("empty ChangeSet emitted payload: %#v", plan.Payloads)
	}
	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		Completeness: InventoryCompletenessComplete,
	})
	if err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	cfg := Config{
		NetworkID: "network-1",
		Policy: ReconcilePolicy{
			Kind:            CompleteInventory,
			PlanningInstant: time.Unix(1, 0).UTC(),
		},
	}
	intent, err := newApplyIntent(cfg, snapshot, cloudAccounts, plan, t.TempDir()+"/payload.json")
	if err != nil {
		t.Fatalf("newApplyIntent() error = %v", err)
	}
	result, err := GuardAndApply(context.Background(), nil, intent, ApplyAuthorization{
		PlanDigest: intent.Digest(),
		Approved:   true,
	})
	if err != nil || result.PatchedCount != 0 {
		t.Fatalf("empty ChangeSet apply = (%d, %v), want no mutation", result.PatchedCount, err)
	}
}

func reconcileTestAccount(t *testing.T, accountID, name, roleName, externalID string, enabled bool) SetupAccount {
	t.Helper()
	id, err := NewAccountID(accountID)
	if err != nil {
		t.Fatal(err)
	}
	roleARN, err := NewRoleARN(id, PartitionAWS, roleName)
	if err != nil {
		t.Fatal(err)
	}
	return SetupAccount{
		AccountID: id, AccountName: name, RoleARN: roleARN, ExternalID: externalID, Enabled: enabled,
	}
}
