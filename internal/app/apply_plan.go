package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type ApplyPlanConfig struct {
	Host                       string
	Username                   string
	Password                   string
	NetworkID                  string
	PlanPath                   string
	APIPrefix                  string
	Insecure                   bool
	Timeout                    time.Duration
	AllowRemovals              bool
	MaxRemovals                int
	MaxRemovalPercent          float64
	AllowUnattendedDestructive bool
	AuthorizationActor         string
}

type ApplyPlanSummary struct {
	Host                string   `json:"host"`
	NetworkID           string   `json:"network_id"`
	PlanPath            string   `json:"plan_path"`
	PayloadSHA256       string   `json:"payload_sha256"`
	PlanDigest          string   `json:"plan_digest"`
	RollbackOutput      string   `json:"rollback_output,omitempty"`
	RollbackSHA256      string   `json:"rollback_sha256,omitempty"`
	ResultJournalOutput string   `json:"result_journal_output"`
	PatchedSetupCount   int      `json:"patched_setup_count"`
	PatchedSetups       []string `json:"patched_setups"`
}

func ApplyPlan(ctx context.Context, cfg ApplyPlanConfig) (*ApplyPlanSummary, error) {
	if err := validateRemovalLimitValues(cfg.MaxRemovals, cfg.MaxRemovalPercent); err != nil {
		return nil, err
	}
	client, err := api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	networkID, err := ResolveNetworkID(ctx, client, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	cfg.NetworkID = networkID
	planPath := strings.TrimSpace(cfg.PlanPath)
	if planPath == "" {
		return nil, fmt.Errorf("plan path is required")
	}
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	var payloads map[string]api.PatchPayload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("decode plan file: %w", err)
	}
	setupIDs := make([]string, 0, len(payloads))
	for setupID, payload := range payloads {
		setupID = strings.TrimSpace(setupID)
		if setupID == "" {
			return nil, fmt.Errorf("plan contains an empty setup id")
		}
		if strings.TrimSpace(payload.Name) != "" && strings.TrimSpace(payload.Name) != setupID {
			return nil, fmt.Errorf("plan setup %s has mismatched payload name %s", setupID, payload.Name)
		}
		setupIDs = append(setupIDs, setupID)
	}
	if len(setupIDs) == 0 {
		return nil, fmt.Errorf("plan contains no setup payloads")
	}
	sort.Strings(setupIDs)
	cloudAccounts, err := client.CloudAccounts(ctx, cfg.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("load current cloud setups before apply: %w", err)
	}
	currentByName := make(map[string]api.CloudAccount, len(cloudAccounts))
	for _, account := range cloudAccounts {
		currentByName[strings.TrimSpace(account.Name)] = account
	}
	targets := make(auditPayloads, len(setupIDs))
	changeSets := make(map[string]ChangeSet, len(setupIDs))
	selectedSetupIDs := make([]SetupID, 0, len(setupIDs))
	for _, setupID := range setupIDs {
		current, ok := currentByName[setupID]
		if !ok {
			return nil, fmt.Errorf("plan setup %s does not exist in Forward", setupID)
		}
		if err := validateCloudAccountPartition(current); err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		payload := payloads[setupID]
		planned := api.CloudAccount{Name: setupID, AssumeRoleInfos: payload.AssumeRoleInfos}
		if len(payload.Regions) > 0 {
			planned.Regions = make(map[string]api.RegionMeta, len(payload.Regions))
			for region, instant := range payload.Regions {
				planned.Regions[region] = api.RegionMeta{TestInstant: instant}
			}
		}
		if err := validateCloudAccountPartition(planned); err != nil {
			return nil, fmt.Errorf("plan setup %s: %w", setupID, err)
		}
		typedSetupID, err := NewSetupID(setupID)
		if err != nil {
			return nil, fmt.Errorf("plan contains invalid setup id %q: %w", setupID, err)
		}
		changes, err := classifyPatchPayload(current, typedSetupID, payload)
		if err != nil {
			return nil, fmt.Errorf("classify plan setup %s: %w", setupID, err)
		}
		targets[setupID] = clonePatchPayload(payload)
		changeSets[setupID] = changes
		selectedSetupIDs = append(selectedSetupIDs, typedSetupID)
	}

	policy := ReconcilePolicy{
		Kind:                 CompleteInventory,
		PlanningInstant:      time.Now().UTC(),
		OrganizationEvidence: AllowMissingOrganizationEvidence,
	}
	intent, err := newPayloadApplyIntent(
		cfg.NetworkID,
		planPath,
		InventorySnapshot{
			Source:           "reviewed apply-plan payload",
			SelectedSetupIDs: selectedSetupIDs,
			Completeness:     InventoryCompletenessComplete,
		},
		policy,
		cloudAccounts,
		targets,
		changeSets,
	)
	if err != nil {
		return nil, err
	}
	actor := strings.TrimSpace(cfg.AuthorizationActor)
	if actor == "" {
		actor = "apply-plan caller"
	}
	applyResult, applyErr := GuardAndApply(ctx, client, intent, ApplyAuthorization{
		PlanDigest:        intent.Digest(),
		Actor:             actor,
		Approved:          true,
		AllowDestructive:  cfg.AllowRemovals,
		MaxRemovals:       cfg.MaxRemovals,
		MaxRemovalPercent: cfg.MaxRemovalPercent,
		// Legacy payload files contain no NQE candidate counts. Preserve that
		// documented file-format limitation while the gateway still applies
		// removal/disable budgets and its no-evidence GovCloud block.
		AllowNoCandidates:          true,
		Unattended:                 true,
		AllowUnattendedDestructive: cfg.AllowUnattendedDestructive,
	})
	patchedSetups := make([]string, 0, applyResult.PatchedCount)
	for _, entry := range applyResult.Journal.Setups {
		if entry.Status == ApplyStatusApplied {
			patchedSetups = append(patchedSetups, entry.SetupID)
		}
	}
	summary := &ApplyPlanSummary{
		Host:                cfg.Host,
		NetworkID:           cfg.NetworkID,
		PlanPath:            planPath,
		PayloadSHA256:       fmt.Sprintf("%x", sha256.Sum256(data)),
		PlanDigest:          intent.Digest(),
		RollbackOutput:      applyResult.RollbackOutput,
		RollbackSHA256:      applyResult.RollbackSHA256,
		ResultJournalOutput: applyResult.JournalOutput,
		PatchedSetupCount:   applyResult.PatchedCount,
		PatchedSetups:       patchedSetups,
	}
	if applyErr != nil {
		if applyResult.JournalOutput != "" {
			return summary, fmt.Errorf("%w; apply result journal: %s", applyErr, applyResult.JournalOutput)
		}
		return summary, applyErr
	}
	return summary, nil
}

func classifyPatchPayload(current api.CloudAccount, setupID SetupID, target api.PatchPayload) (ChangeSet, error) {
	currentSetup, err := adaptCurrentSetup(cloudSetupMetadata{
		setupID:             setupID,
		cloudType:           current.Type,
		proxyServerID:       current.ProxyServerID,
		regionToProxyServer: current.RegionToProxyServerID,
		regions:             current.Regions,
		assumeRoleInfos:     current.AssumeRoleInfos,
	})
	if err != nil {
		return ChangeSet{}, err
	}
	targetRegions := make(map[string]api.RegionMeta, len(target.Regions))
	for region, instant := range target.Regions {
		targetRegions[region] = api.RegionMeta{TestInstant: instant}
	}
	targetSetup, err := adaptCurrentSetup(cloudSetupMetadata{
		setupID:             setupID,
		cloudType:           target.Type,
		proxyServerID:       target.ProxyServerID,
		regionToProxyServer: target.RegionToProxyServerID,
		regions:             targetRegions,
		assumeRoleInfos:     target.AssumeRoleInfos,
	})
	if err != nil {
		return ChangeSet{}, err
	}
	return diffSetup(currentSetup, DesiredSetup{
		SetupID:  targetSetup.SetupID,
		Metadata: targetSetup.Metadata,
		Accounts: targetSetup.Accounts,
	}), nil
}
