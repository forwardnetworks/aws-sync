package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

// ApplyStatus is the durable disposition of one setup in an apply journal.
type ApplyStatus string

const (
	ApplyStatusPlanned    ApplyStatus = "planned"
	ApplyStatusPending    ApplyStatus = "pending"
	ApplyStatusApplied    ApplyStatus = "applied"
	ApplyStatusConflicted ApplyStatus = "conflicted"
	ApplyStatusFailed     ApplyStatus = "failed"
)

// ApplyJournalEntry records the recoverable state of one planned setup.
type ApplyJournalEntry struct {
	SetupID    string        `json:"setup_id"`
	Status     ApplyStatus   `json:"status"`
	History    []ApplyStatus `json:"history"`
	HasChanges bool          `json:"has_changes"`
	Error      string        `json:"error,omitempty"`
}

// ApplyJournal is atomically rewritten after every setup disposition change.
type ApplyJournal struct {
	PlanDigest    string                   `json:"plan_digest"`
	NetworkID     string                   `json:"network_id"`
	Authorization ApplyAuthorizationRecord `json:"authorization"`
	UpdatedAt     time.Time                `json:"updated_at"`
	Setups        []ApplyJournalEntry      `json:"setups"`
}

// ApplyAuthorizationRecord is the audit-safe authorization persisted with the
// digest it approved. It contains no credentials.
type ApplyAuthorizationRecord struct {
	PlanDigest                 string  `json:"plan_digest"`
	Actor                      string  `json:"actor"`
	Approved                   bool    `json:"approved"`
	AllowDestructive           bool    `json:"allow_destructive"`
	MaxRemovals                int     `json:"max_removals"`
	MaxRemovalPercent          float64 `json:"max_removal_percent"`
	AllowNoCandidates          bool    `json:"allow_no_candidates"`
	Unattended                 bool    `json:"unattended"`
	AllowUnattendedDestructive bool    `json:"allow_unattended_destructive"`
}

// ApplyAuthorization is the single authorization record accepted by the
// account-list mutation gateway.
type ApplyAuthorization struct {
	PlanDigest                 string
	Actor                      string
	Approved                   bool
	AllowDestructive           bool
	MaxRemovals                int
	MaxRemovalPercent          float64
	AllowNoCandidates          bool
	Unattended                 bool
	AllowUnattendedDestructive bool
}

// ApplyResult is returned even when an apply is partial or blocked.
type ApplyResult struct {
	PatchedCount   int
	Blocked        bool
	RollbackOutput string
	RollbackSHA256 string
	JournalOutput  string
	Journal        ApplyJournal
}

// ApplyIntent is immutable after construction. Its state is private and every
// mutable input is cloned by newApplyIntent.
type ApplyIntent struct {
	state *applyIntentState
}

type applyIntentState struct {
	networkID  string
	outputPath string
	snapshot   InventorySnapshot
	policy     ReconcilePolicy
	baselines  auditPayloads
	targets    auditPayloads
	setups     []applySetupIntent
	digest     string
}

type applySetupIntent struct {
	setupID                   string
	baseline                  api.PatchPayload
	target                    api.PatchPayload
	changes                   ChangeSet
	discoveredCandidateCount  int
	discoveredOrgUnitRowCount int
}

type applyDigestMaterial struct {
	Version   int                    `json:"version"`
	NetworkID string                 `json:"network_id"`
	Baselines auditPayloads          `json:"baselines"`
	Snapshot  InventorySnapshot      `json:"snapshot"`
	Policy    applyDigestPolicy      `json:"policy"`
	Targets   auditPayloads          `json:"targets"`
	Changes   []applyDigestChangeSet `json:"changes"`
}

type applyDigestPolicy struct {
	Kind                 ReconcilePolicyKind        `json:"kind"`
	OrganizationEvidence OrganizationEvidencePolicy `json:"organization_evidence"`
	DefaultRoleName      string                     `json:"default_role_name"`
	UniformExternalID    *string                    `json:"uniform_external_id"`
	ExternalIDByAccount  map[AccountID]string       `json:"external_id_by_account"`
	Operations           []ExplicitAccountOperation `json:"operations"`
}

type applyDigestChangeSet struct {
	SetupID          string `json:"setup_id"`
	Add              int    `json:"add"`
	Enable           int    `json:"enable"`
	Disable          int    `json:"disable"`
	Remove           int    `json:"remove"`
	Rename           int    `json:"rename"`
	RotateExternalID int    `json:"rotate_external_id"`
	ChangeRole       int    `json:"change_role"`
	SetupMetadata    int    `json:"setup_metadata"`
}

func newApplyIntent(
	cfg Config,
	snapshot *InventorySnapshot,
	cloudAccounts []api.CloudAccount,
	plan *patchPlan,
	outputPath string,
) (ApplyIntent, error) {
	if snapshot == nil {
		return ApplyIntent{}, fmt.Errorf("apply intent requires an inventory snapshot")
	}
	setupIDs := selectedSetupIDs(plan.Setups)
	baselines, err := buildRollbackPayloads(cloudAccounts, setupIDs)
	if err != nil {
		return ApplyIntent{}, err
	}
	snapshotCopy := cloneInventorySnapshot(*snapshot)
	if strings.TrimSpace(snapshotCopy.Source) == "" {
		snapshotCopy.Source = strings.TrimSpace(cfg.Source)
	}
	snapshotCopy.NetworkID = strings.TrimSpace(cfg.NetworkID)
	snapshotCopy.SnapshotID = strings.TrimSpace(cfg.SnapshotID)

	state := &applyIntentState{
		networkID:  strings.TrimSpace(cfg.NetworkID),
		outputPath: outputPath,
		snapshot:   snapshotCopy,
		policy:     cloneReconcilePolicy(cfg.Policy),
		baselines:  cloneAuditPayloads(baselines),
		targets:    cloneAuditPayloads(plan.Payloads),
		setups:     make([]applySetupIntent, 0, len(plan.Setups)),
	}
	for _, setup := range plan.Setups {
		state.setups = append(state.setups, applySetupIntent{
			setupID:                   setup.SetupID,
			baseline:                  clonePatchPayload(baselines[setup.SetupID]),
			target:                    clonePatchPayload(setup.Payload),
			changes:                   cloneChangeSet(setup.ChangeSet),
			discoveredCandidateCount:  setup.DiscoveredCandidateCount,
			discoveredOrgUnitRowCount: setup.DiscoveredOrgUnitRowCount,
		})
	}
	sort.Slice(state.setups, func(i, j int) bool {
		return state.setups[i].setupID < state.setups[j].setupID
	})
	digest, err := computeApplyIntentDigest(state)
	if err != nil {
		return ApplyIntent{}, err
	}
	state.digest = digest
	return ApplyIntent{state: state}, nil
}

// newPayloadApplyIntent is the compatibility constructor for operator-authored
// payload workflows. Callers must classify every target through the typed
// reconciliation diff before constructing the immutable gateway intent.
func newPayloadApplyIntent(
	networkID string,
	outputPath string,
	snapshot InventorySnapshot,
	policy ReconcilePolicy,
	cloudAccounts []api.CloudAccount,
	targets auditPayloads,
	changes map[string]ChangeSet,
) (ApplyIntent, error) {
	if len(targets) == 0 {
		return ApplyIntent{}, fmt.Errorf("apply intent requires at least one target payload")
	}
	setupIDs := make([]string, 0, len(targets))
	for setupID := range targets {
		setupIDs = append(setupIDs, setupID)
		if _, ok := changes[setupID]; !ok {
			return ApplyIntent{}, fmt.Errorf("apply intent target %s has no classified change set", setupID)
		}
	}
	sort.Strings(setupIDs)
	baselines, err := buildRollbackPayloads(cloudAccounts, setupIDs)
	if err != nil {
		return ApplyIntent{}, err
	}
	snapshot.NetworkID = strings.TrimSpace(networkID)

	state := &applyIntentState{
		networkID:  strings.TrimSpace(networkID),
		outputPath: outputPath,
		snapshot:   cloneInventorySnapshot(snapshot),
		policy:     cloneReconcilePolicy(policy),
		baselines:  cloneAuditPayloads(baselines),
		targets:    cloneAuditPayloads(targets),
		setups:     make([]applySetupIntent, 0, len(setupIDs)),
	}
	for _, setupID := range setupIDs {
		state.setups = append(state.setups, applySetupIntent{
			setupID:  setupID,
			baseline: clonePatchPayload(baselines[setupID]),
			target:   clonePatchPayload(targets[setupID]),
			changes:  cloneChangeSet(changes[setupID]),
		})
	}
	digest, err := computeApplyIntentDigest(state)
	if err != nil {
		return ApplyIntent{}, err
	}
	state.digest = digest
	return ApplyIntent{state: state}, nil
}

// Digest returns the SHA-256 approval binding for this immutable intent.
func (i ApplyIntent) Digest() string {
	if i.state == nil {
		return ""
	}
	return i.state.digest
}

func computeApplyIntentDigest(state *applyIntentState) (string, error) {
	changes := make([]applyDigestChangeSet, 0, len(state.setups))
	for _, setup := range state.setups {
		changes = append(changes, applyDigestChangeSet{
			SetupID:          setup.setupID,
			Add:              len(setup.changes.Add),
			Enable:           len(setup.changes.Enable),
			Disable:          len(setup.changes.Disable),
			Remove:           len(setup.changes.Remove),
			Rename:           len(setup.changes.Rename),
			RotateExternalID: len(setup.changes.RotateExternalID),
			ChangeRole:       len(setup.changes.ChangeRole),
			SetupMetadata:    len(setup.changes.SetupMetadata),
		})
	}
	data, err := json.Marshal(applyDigestMaterial{
		Version:   2,
		NetworkID: state.networkID,
		Baselines: approvalDigestPayloads(state.baselines),
		Snapshot:  state.snapshot,
		Policy:    approvalDigestPolicy(state.policy),
		Targets:   approvalDigestPayloads(state.targets),
		Changes:   changes,
	})
	if err != nil {
		return "", fmt.Errorf("encode immutable apply intent: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func approvalDigestPolicy(policy ReconcilePolicy) applyDigestPolicy {
	// PlanningInstant is execution metadata, not a reconciliation decision.
	// The exact bytes it produces remain covered by payload_sha256.
	return applyDigestPolicy{
		Kind:                 policy.Kind,
		OrganizationEvidence: policy.OrganizationEvidence,
		DefaultRoleName:      policy.DefaultRoleName,
		UniformExternalID:    policy.UniformExternalID,
		ExternalIDByAccount:  policy.ExternalIDByAccount,
		Operations:           policy.Operations,
	}
}

func approvalDigestPayloads(payloads auditPayloads) auditPayloads {
	result := cloneAuditPayloads(payloads)
	for setupID, payload := range result {
		// Region membership is approval-relevant; volatile test instants are not.
		for region := range payload.Regions {
			payload.Regions[region] = 0
		}
		result[setupID] = payload
	}
	return result
}

// GuardAndApply is the sole Phase 3a account-list PATCH gateway. Forward does
// not expose an ETag or version, so the immediate re-read below is only a weak
// conflict detector. It cannot make the following full-list PATCH safe from a
// concurrent write in the GET/PATCH window and must never be described as CAS.
func GuardAndApply(
	ctx context.Context,
	client *api.Client,
	intent ApplyIntent,
	authorization ApplyAuthorization,
) (ApplyResult, error) {
	if intent.state == nil {
		return ApplyResult{}, fmt.Errorf("apply intent is required")
	}
	state := intent.state
	result := ApplyResult{
		JournalOutput: resultJournalPath(state.outputPath),
		Journal: ApplyJournal{
			PlanDigest: state.digest,
			NetworkID:  state.networkID,
			Authorization: ApplyAuthorizationRecord{
				PlanDigest:                 strings.TrimSpace(authorization.PlanDigest),
				Actor:                      strings.TrimSpace(authorization.Actor),
				Approved:                   authorization.Approved,
				AllowDestructive:           authorization.AllowDestructive,
				MaxRemovals:                authorization.MaxRemovals,
				MaxRemovalPercent:          authorization.MaxRemovalPercent,
				AllowNoCandidates:          authorization.AllowNoCandidates,
				Unattended:                 authorization.Unattended,
				AllowUnattendedDestructive: authorization.AllowUnattendedDestructive,
			},
			Setups: make([]ApplyJournalEntry, 0, len(state.setups)),
		},
	}
	for _, setup := range state.setups {
		result.Journal.Setups = append(result.Journal.Setups, ApplyJournalEntry{
			SetupID:    setup.setupID,
			Status:     ApplyStatusPlanned,
			History:    []ApplyStatus{ApplyStatusPlanned},
			HasChanges: !setup.changes.Empty(),
		})
	}
	if err := persistApplyJournal(&result); err != nil {
		return result, err
	}
	if !intentHasChanges(state) {
		return result, nil
	}
	if err := validateApplyAuthorization(state, authorization); err != nil {
		result.Blocked = true
		markChangedEntries(&result.Journal, ApplyStatusFailed, err.Error())
		_ = persistApplyJournal(&result)
		return result, err
	}

	for index := range result.Journal.Setups {
		if !result.Journal.Setups[index].HasChanges {
			continue
		}
		setJournalStatus(&result.Journal.Setups[index], ApplyStatusPending, "")
	}
	if err := persistApplyJournal(&result); err != nil {
		return result, err
	}

	result.RollbackOutput = rollbackPath(state.outputPath)
	rollbackSHA256, err := writeAuditPayloads(result.RollbackOutput, state.baselines)
	if err != nil {
		return failPendingApply(result, fmt.Errorf("write pre-apply rollback payload: %w", err))
	}
	result.RollbackSHA256 = rollbackSHA256
	if _, err := writeAuditPayloads(auditPath(state.outputPath), state.targets); err != nil {
		return failPendingApply(result, err)
	}

	for _, setup := range state.setups {
		if setup.changes.Empty() {
			continue
		}
		entry := journalEntry(&result.Journal, setup.setupID)
		current, err := client.CloudAccounts(ctx, state.networkID)
		if err != nil {
			wrapped := fmt.Errorf("reload cloud setup %s immediately before apply: %w", setup.setupID, err)
			setJournalStatus(entry, ApplyStatusFailed, wrapped.Error())
			_ = persistApplyJournal(&result)
			return result, wrapped
		}
		actual, err := buildRollbackPayloads(current, []string{setup.setupID})
		if err != nil {
			setJournalStatus(entry, ApplyStatusConflicted, err.Error())
			_ = persistApplyJournal(&result)
			return result, err
		}
		if !reflect.DeepEqual(setup.baseline, actual[setup.setupID]) {
			conflict := fmt.Errorf(
				"selected Forward cloud setup state changed after planning for setup %s; no PATCH was sent for that setup; rerun the dry plan (the last-second re-read is only a weak mitigation because Forward provides no atomic compare-and-swap)",
				setup.setupID,
			)
			setJournalStatus(entry, ApplyStatusConflicted, conflict.Error())
			_ = persistApplyJournal(&result)
			return result, conflict
		}
		if err := client.PatchCloudAccount(ctx, state.networkID, setup.setupID, setup.target); err != nil {
			wrapped := fmt.Errorf("patch setup %s: %w", setup.setupID, err)
			setJournalStatus(entry, ApplyStatusFailed, wrapped.Error())
			_ = persistApplyJournal(&result)
			return result, wrapped
		}
		result.PatchedCount++
		setJournalStatus(entry, ApplyStatusApplied, "")
		if err := persistApplyJournal(&result); err != nil {
			return result, fmt.Errorf("setup %s was patched but its applied result could not be journaled: %w", setup.setupID, err)
		}
	}
	return result, nil
}

func validateApplyAuthorization(state *applyIntentState, authorization ApplyAuthorization) error {
	if !authorization.Approved {
		return fmt.Errorf("apply authorization is required")
	}
	if strings.TrimSpace(authorization.PlanDigest) == "" ||
		!strings.EqualFold(authorization.PlanDigest, state.digest) {
		return fmt.Errorf(
			"reviewed plan changed before apply: expected plan digest %s, got %s; no PATCH was sent",
			strings.TrimSpace(authorization.PlanDigest),
			state.digest,
		)
	}

	stats := destructiveRemovalStats(state)
	totalDestructive := 0
	totalRemoved := 0
	for _, setup := range state.setups {
		totalDestructive += len(setup.changes.Remove) + len(setup.changes.Disable)
		totalRemoved += len(setup.changes.Remove)
	}
	if totalDestructive == 0 {
		return nil
	}
	if !authorization.AllowDestructive {
		return fmt.Errorf("planned account removals or disables require --allow-removals")
	}
	if totalRemoved > 0 && strings.EqualFold(strings.TrimSpace(state.snapshot.Source), "nqe") {
		return nqeCompleteInventoryError()
	}
	if totalRemoved > 0 && state.policy.Kind == CompleteInventory && !state.snapshot.Completeness.Proven() {
		return incompleteInventoryPolicyError(state.snapshot)
	}
	if err := requireRemovalBounds(stats, authorization.MaxRemovals, authorization.MaxRemovalPercent); err != nil {
		return err
	}
	if err := validateRemovalStats(stats, authorization.MaxRemovals, authorization.MaxRemovalPercent); err != nil {
		return err
	}
	if err := validateDestructiveEvidence(state, authorization); err != nil {
		return err
	}
	if err := unattendedDestructiveApplyError(state, authorization.Unattended, authorization.AllowUnattendedDestructive); err != nil {
		return err
	}
	return nil
}

func unattendedDestructiveApplyError(state *applyIntentState, unattended, allowed bool) error {
	if !unattended || allowed {
		return nil
	}
	totalDestructive := 0
	for _, setup := range state.setups {
		totalDestructive += len(setup.changes.Remove) + len(setup.changes.Disable)
	}
	if totalDestructive == 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing unattended destructive apply without --allow-unattended-destructive: plan removes or disables %d account(s); Forward provides no atomic compare-and-swap",
		totalDestructive,
	)
}

func validateDestructiveEvidence(state *applyIntentState, authorization ApplyAuthorization) error {
	if state.policy.OrganizationEvidence == ReviewedAuthoritativeInventory {
		return nil
	}
	missingEvidence := make([]string, 0)
	hasDisable := false
	for _, setup := range state.setups {
		if len(setup.changes.Remove)+len(setup.changes.Disable) == 0 {
			continue
		}
		hasDisable = hasDisable || len(setup.changes.Disable) > 0
		evidenceVisible := organizationDiscoveryVisible(
			setup.discoveredCandidateCount,
			setup.discoveredOrgUnitRowCount,
		)
		if setup.discoveredCandidateCount == 0 && !authorization.AllowNoCandidates {
			if len(setup.changes.Disable) == 0 {
				return fmt.Errorf("planned removals with no uncollected candidate accounts visible require --allow-no-candidates")
			}
			return fmt.Errorf("planned removals or disables with no uncollected candidate accounts visible require --allow-no-candidates")
		}
		if !evidenceVisible && extractRolePartition(setup.baseline.AssumeRoleInfos) == "aws-us-gov" {
			if len(setup.changes.Disable) == 0 {
				return fmt.Errorf("GovCloud account removals require positive AWS Organizations evidence; use sync-accounts with an authoritative reviewed manifest when Organizations is unavailable")
			}
			return fmt.Errorf("GovCloud account removals or disables require positive AWS Organizations evidence; use sync-accounts with an authoritative reviewed manifest when Organizations is unavailable")
		}
		if !evidenceVisible && state.policy.OrganizationEvidence == RequireOrganizationEvidence {
			missingEvidence = append(missingEvidence, setup.setupID)
		}
	}
	if len(missingEvidence) > 0 {
		sort.Strings(missingEvidence)
		if !hasDisable {
			return fmt.Errorf(
				"planned removals with no AWS Organizations evidence in NQE for setup(s): %s require --allow-no-org-evidence",
				strings.Join(missingEvidence, ", "),
			)
		}
		return fmt.Errorf(
			"planned removals or disables with no AWS Organizations evidence in NQE for setup(s): %s require --allow-no-org-evidence",
			strings.Join(missingEvidence, ", "),
		)
	}
	return nil
}

func destructiveRemovalStats(state *applyIntentState) []removalStat {
	stats := make([]removalStat, 0, len(state.setups))
	for _, setup := range state.setups {
		stats = append(stats, removalStat{
			SetupID:         setup.setupID,
			ConfiguredCount: len(setup.baseline.AssumeRoleInfos),
			RemovedCount:    len(setup.changes.Remove) + len(setup.changes.Disable),
		})
	}
	return stats
}

func intentHasChanges(state *applyIntentState) bool {
	for _, setup := range state.setups {
		if !setup.changes.Empty() {
			return true
		}
	}
	return false
}

func failPendingApply(result ApplyResult, err error) (ApplyResult, error) {
	markChangedEntries(&result.Journal, ApplyStatusFailed, err.Error())
	_ = persistApplyJournal(&result)
	return result, err
}

func markChangedEntries(journal *ApplyJournal, status ApplyStatus, message string) {
	for index := range journal.Setups {
		entry := &journal.Setups[index]
		if !entry.HasChanges || entry.Status == ApplyStatusApplied {
			continue
		}
		setJournalStatus(entry, status, message)
	}
}

func journalEntry(journal *ApplyJournal, setupID string) *ApplyJournalEntry {
	for index := range journal.Setups {
		if journal.Setups[index].SetupID == setupID {
			return &journal.Setups[index]
		}
	}
	return nil
}

func setJournalStatus(entry *ApplyJournalEntry, status ApplyStatus, message string) {
	if entry == nil {
		return
	}
	entry.Status = status
	entry.Error = message
	if len(entry.History) == 0 || entry.History[len(entry.History)-1] != status {
		entry.History = append(entry.History, status)
	}
}

func persistApplyJournal(result *ApplyResult) error {
	result.Journal.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(result.Journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode apply result journal: %w", err)
	}
	if err := writeFileAtomic0600(result.JournalOutput, data); err != nil {
		return fmt.Errorf("write apply result journal: %w", err)
	}
	return nil
}

func resultJournalPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + ".result"
	}
	return strings.TrimSuffix(outputPath, ext) + ".result" + ext
}

func clonePatchPayload(payload api.PatchPayload) api.PatchPayload {
	return api.PatchPayload{
		Type:                  payload.Type,
		Name:                  payload.Name,
		Regions:               cloneInt64Map(payload.Regions),
		RegionToProxyServerID: cloneStringMap(payload.RegionToProxyServerID),
		ProxyServerID:         payload.ProxyServerID,
		AssumeRoleInfos:       append([]api.AssumeRoleInfo(nil), payload.AssumeRoleInfos...),
	}
}

func cloneAuditPayloads(payloads auditPayloads) auditPayloads {
	result := make(auditPayloads, len(payloads))
	for setupID, payload := range payloads {
		result[setupID] = clonePatchPayload(payload)
	}
	return result
}

func cloneInventorySnapshot(snapshot InventorySnapshot) InventorySnapshot {
	result := snapshot
	result.SelectedSetupIDs = append([]SetupID(nil), snapshot.SelectedSetupIDs...)
	result.DiscoveredAccounts = append([]DiscoveredAccount(nil), snapshot.DiscoveredAccounts...)
	result.IgnoredAccounts = append([]AccountSummary(nil), snapshot.IgnoredAccounts...)
	result.SkippedRows = append([]MalformedNQERowSummary(nil), snapshot.SkippedRows...)
	if snapshot.ExpectedRowCount != nil {
		value := *snapshot.ExpectedRowCount
		result.ExpectedRowCount = &value
	}
	if snapshot.SnapshotTime != nil {
		value := *snapshot.SnapshotTime
		result.SnapshotTime = &value
	}
	return result
}

func cloneReconcilePolicy(policy ReconcilePolicy) ReconcilePolicy {
	result := policy
	result.ExternalIDByAccount = make(map[AccountID]string, len(policy.ExternalIDByAccount))
	for accountID, externalID := range policy.ExternalIDByAccount {
		result.ExternalIDByAccount[accountID] = externalID
	}
	result.Operations = append([]ExplicitAccountOperation(nil), policy.Operations...)
	if policy.UniformExternalID != nil {
		value := *policy.UniformExternalID
		result.UniformExternalID = &value
	}
	return result
}

func cloneChangeSet(changes ChangeSet) ChangeSet {
	return ChangeSet{
		Add:              cloneAccountChanges(changes.Add),
		Enable:           cloneAccountChanges(changes.Enable),
		Disable:          cloneAccountChanges(changes.Disable),
		Remove:           cloneAccountChanges(changes.Remove),
		Rename:           cloneAccountChanges(changes.Rename),
		RotateExternalID: cloneAccountChanges(changes.RotateExternalID),
		ChangeRole:       cloneAccountChanges(changes.ChangeRole),
		SetupMetadata:    append([]SetupMetadataChange(nil), changes.SetupMetadata...),
	}
}

func cloneAccountChanges(changes []AccountChange) []AccountChange {
	result := make([]AccountChange, 0, len(changes))
	for _, change := range changes {
		result = append(result, accountChange(change.AccountID, change.Before, change.After))
	}
	return result
}
