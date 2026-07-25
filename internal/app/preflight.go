package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type PreflightSummary struct {
	Host             string           `json:"host"`
	NetworkID        string           `json:"network_id"`
	SnapshotID       string           `json:"snapshot_id,omitempty"`
	QueryID          string           `json:"query_id"`
	QueryOverride    bool             `json:"query_override"`
	QuerySetupParam  string           `json:"query_setup_param,omitempty"`
	SetupIDs         []string         `json:"setup_ids,omitempty"`
	SelectedSetupIDs []string         `json:"selected_setup_ids,omitempty"`
	Ready            bool             `json:"ready"`
	FetchedItemCount int              `json:"fetched_item_count"`
	IgnoredNQEItems  int              `json:"ignored_nqe_item_count,omitempty"`
	PlannedSetups    []SetupSummary   `json:"planned_setups,omitempty"`
	SkippedSetups    []SkipSummary    `json:"skipped_setups,omitempty"`
	Checks           []PreflightCheck `json:"checks"`
}

type PreflightCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func Preflight(ctx context.Context, cfg Config) (*PreflightSummary, error) {
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
	result := &PreflightSummary{
		Host:            cfg.Host,
		NetworkID:       cfg.NetworkID,
		SnapshotID:      cfg.SnapshotID,
		QueryID:         cfg.QueryID,
		QueryOverride:   cfg.QueryID != "",
		QuerySetupParam: strings.TrimSpace(cfg.QuerySetupParam),
		SetupIDs:        cleanSetupIDs(cfg.SetupIDs),
		Ready:           true,
	}

	if cfg.SnapshotID != "" {
		result.pass("snapshot_selection", fmt.Sprintf("using explicit snapshot %s", cfg.SnapshotID))
	} else {
		if err := pinLatestProcessedSnapshot(ctx, client, &cfg); err != nil {
			result.fail("latest_processed_snapshot", err.Error())
			return result, nil
		}
		result.SnapshotID = cfg.SnapshotID
		result.pass("latest_processed_snapshot", fmt.Sprintf("pinned latest processed snapshot %s", cfg.SnapshotID))
		if cfg.MaxSnapshotAge > 0 {
			result.pass("snapshot_freshness", "pinned snapshot is fresh enough")
		}
	}

	if err := validateQuerySetupParam(cfg); err != nil {
		result.fail("nqe_parameters", err.Error())
		return result, nil
	}
	query, queryID, parameters := queryInputs(cfg)
	queryResult, err := client.QueryAWSAccountsWithMetadata(ctx, cfg.NetworkID, cfg.SnapshotID, query, queryID, parameters, cfg.SetupIDs)
	if err != nil {
		result.fail("nqe_aws_accounts", err.Error())
		return result, nil
	}
	items := queryResult.Items
	result.FetchedItemCount = len(items)
	if len(items) == 0 {
		result.fail("nqe_aws_accounts", "query returned no AWS account rows")
	} else {
		result.pass("nqe_aws_accounts", fmt.Sprintf("query returned %d AWS account rows", len(items)))
	}

	cloudAccounts, err := client.CloudAccounts(ctx, cfg.NetworkID)
	if err != nil {
		result.fail("forward_cloud_setups", err.Error())
		return result, nil
	}

	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, nqeParseOptionsFromQueryResult(queryResult, cfg.AllowMalformedRows))
	if err != nil {
		result.fail("patch_plan", err.Error())
		return result, nil
	}

	if len(cloudAccounts) == 0 {
		result.fail("forward_cloud_setups", "Forward returned no cloud account setups")
	} else {
		result.pass("forward_cloud_setups", fmt.Sprintf("Forward returned %d cloud account setups", len(cloudAccounts)))
	}
	setupIDValues := SetupIDsFromSnapshot(snapshot)
	awsSetups, err := adaptCloudAccountsBySetupID(cloudAccounts, cfg.SetupIDs)
	if err != nil {
		result.fail("aws_account_setups", err.Error())
		return result, nil
	}
	partitionIssues := make([]string, 0)
	for setupID, setup := range awsSetups {
		if err := validateCloudAccountPartitionFromMetadata(setup); err != nil {
			partitionIssues = append(partitionIssues, fmt.Sprintf("%s: %s", setupID, err))
		}
	}
	sort.Strings(partitionIssues)
	if len(partitionIssues) > 0 {
		result.fail("aws_partition_consistency", strings.Join(partitionIssues, "; "))
		return result, nil
	}
	result.pass("aws_partition_consistency", "IAM role ARN partitions match the configured AWS regions")
	if len(setupIDValues) == 0 && len(awsSetups) > 1 {
		result.fail("nqe_setup_id_differentiator", "NQE rows did not include Cloud Setup ID; multiple AWS setups cannot be separated. Use the default inline query or a saved query that selects cloudAccount.cloudSetupId as Cloud Setup ID.")
	} else if len(setupIDValues) == 0 {
		result.pass("nqe_setup_id_differentiator", "NQE rows did not include Cloud Setup ID, but only one eligible AWS setup is in scope")
	} else {
		result.pass("nqe_setup_id_differentiator", fmt.Sprintf("NQE rows include setup IDs: %s", strings.Join(setupIDValues, ", ")))
	}

	planOptions, err := buildPlanOptionsFromConfig(cfg)
	if err != nil {
		result.fail("patch_plan", err.Error())
		return result, nil
	}
	plan, err := buildPlanFromSnapshot(snapshot, cloudAccounts, cfg.SetupIDs, planOptions)
	if err != nil {
		result.fail("patch_plan", err.Error())
		return result, nil
	}
	result.pass("patch_plan", fmt.Sprintf("planned %d eligible setup updates", len(plan.Setups)))
	summary := buildSummary(cfg, "", "", "", "", nil, len(items), plan, 0)
	result.SelectedSetupIDs = summary.SelectedSetupIDs
	result.PlannedSetups = summary.PlannedSetups
	result.SkippedSetups = summary.SkippedSetups
	result.IgnoredNQEItems = summary.IgnoredNQEItemCount
	if summary.IgnoredNQEItemCount > 0 {
		result.warn("nqe_account_id_validation", fmt.Sprintf("ignored %d NQE row(s) with invalid AWS account IDs", summary.IgnoredNQEItemCount))
	} else {
		result.pass("nqe_account_id_validation", "all NQE AWS account IDs are valid 12-digit IDs")
	}
	if plan.HasRemovals() {
		result.fail("account_removals", "planned account removals require review and --allow-removals for apply")
	} else {
		result.pass("account_removals", "no account removals planned")
	}
	if plan.HasRemovals() {
		if err := requireRemovalBounds(plan.removalStats(), cfg.MaxRemovals, cfg.MaxRemovalPercent); err != nil {
			result.fail("removal_blast_radius", err.Error())
		} else if err := validateRemovalStats(plan.removalStats(), cfg.MaxRemovals, cfg.MaxRemovalPercent); err != nil {
			result.fail("removal_blast_radius", err.Error())
		} else {
			result.pass("removal_blast_radius", "planned removals are within the configured count and percentage limits")
		}
	}
	if plan.HasCandidateRisk() {
		if plan.HasRemovals() {
			result.fail("management_account_discovery", "one or more selected setups have no new uncollected candidate accounts visible")
		} else {
			result.warn("management_account_discovery", "no new uncollected candidate accounts are visible; additive mode preserves configured accounts")
		}
	} else {
		result.pass("management_account_discovery", "uncollected candidate accounts are visible in Forward NQE")
	}
	missingOrgEvidenceSetups := plansWithoutOrganizationEvidence(plan)
	if len(missingOrgEvidenceSetups) == 0 {
		result.pass("aws_organizations_evidence", "Forward NQE exposes candidate rows or Organizational Unit IDs for every selected setup")
	} else if plan.HasGovCloudRemovalsWithoutOrganizationEvidence() {
		result.fail(
			"aws_organizations_evidence",
			fmt.Sprintf("GovCloud removals are blocked without positive Organizations evidence for: %s; use sync-accounts with an authoritative reviewed manifest if Organizations is unavailable", strings.Join(missingOrgEvidenceSetups, ", ")),
		)
	} else if plan.HasNoOrganizationEvidenceForRemovals() {
		result.fail(
			"aws_organizations_evidence",
			fmt.Sprintf("selected setups without org evidence: %s; apply requires --allow-no-org-evidence", strings.Join(missingOrgEvidenceSetups, ", ")),
		)
	} else {
		result.pass(
			"aws_organizations_evidence",
			fmt.Sprintf("some selected setups have no organizational evidence: %s", strings.Join(missingOrgEvidenceSetups, ", ")),
		)
	}
	return result, nil
}

func plansWithoutOrganizationEvidence(plan *patchPlan) []string {
	missing := make([]string, 0)
	for _, setup := range plan.Setups {
		if organizationDiscoveryVisible(setup.DiscoveredCandidateCount, setup.DiscoveredOrgUnitRowCount) {
			continue
		}
		missing = append(missing, setup.SetupID)
	}
	sort.Strings(missing)
	return missing
}

func (s *PreflightSummary) pass(name, message string) {
	s.Checks = append(s.Checks, PreflightCheck{Name: name, Status: "pass", Message: message})
}

func (s *PreflightSummary) fail(name, message string) {
	s.Ready = false
	s.Checks = append(s.Checks, PreflightCheck{Name: name, Status: "fail", Message: message})
}

func (s *PreflightSummary) warn(name, message string) {
	s.Checks = append(s.Checks, PreflightCheck{Name: name, Status: "warn", Message: message})
}
