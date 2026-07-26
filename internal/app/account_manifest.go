package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

const (
	manifestNQESimilarityThreshold        = 0.95
	manifestConfiguredDifferenceThreshold = 0.20
)

type AWSAccountManifestEntry struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

func LoadAWSAccountManifest(path string) ([]AWSOrganizationAccount, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("--accounts-file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open accounts file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var entries []AWSAccountManifestEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode accounts file: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("accounts file contains no accounts")
	}

	seen := make(map[string]bool, len(entries))
	accounts := make([]AWSOrganizationAccount, 0, len(entries))
	for index, entry := range entries {
		accountID := strings.TrimSpace(entry.ID)
		if _, err := NewAccountID(accountID); err != nil {
			return nil, fmt.Errorf("accounts file entry %d has invalid AWS account ID %q; expected 12 digits", index+1, entry.ID)
		}
		if seen[accountID] {
			return nil, fmt.Errorf("accounts file contains duplicate AWS account ID %s", accountID)
		}
		seen[accountID] = true
		accountName := strings.TrimSpace(entry.Name)
		if accountName == "" {
			accountName = accountID
		}
		accounts = append(accounts, AWSOrganizationAccount{ID: accountID, Name: accountName})
	}
	return accounts, nil
}

func RunAWSAccountManifest(ctx context.Context, cfg AWSOrganizationConfig, accounts []AWSOrganizationAccount) (*Summary, error) {
	return RunAWSOrganizations(ctx, cfg, AWSOrganizationSource{
		Accounts:         accounts,
		Partition:        cfg.Partition,
		Source:           "account_manifest",
		DiscoveryMessage: "Account inventory came from the explicitly reviewed manifest; AWS Organizations was not queried",
	})
}

func SyncAWSAccountManifest(ctx context.Context, cfg Config, accounts []AWSOrganizationAccount) (*Summary, error) {
	cfg.AuthoritativeInput = true
	if cfg.Policy.Kind == "" {
		cfg.Policy = NewAuthoritativeManifestReconcilePolicy(time.Now().UTC())
	} else {
		cfg.Policy.Kind = CompleteInventory
		cfg.Policy.OrganizationEvidence = ReviewedAuthoritativeInventory
		cfg = prepareReconcileConfig(cfg, time.Now().UTC())
	}
	setupIDs := cleanSetupIDs(cfg.SetupIDs)
	if len(setupIDs) != 1 {
		return nil, fmt.Errorf("account-manifest sync requires exactly one --setup-id")
	}
	setupID := setupIDs[0]
	client, err := api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	networkID, err := ResolveNetworkID(ctx, client, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	cfg.NetworkID = networkID
	cfg.Source = "account_manifest"

	cloudAccounts, err := client.CloudAccounts(ctx, networkID)
	if err != nil {
		return nil, err
	}
	warnings := inspectManifestInventoryShape(ctx, client, cfg, setupID, accounts, cloudAccounts)
	discovered, err := adaptManifestAccountsToSetupRows(accounts, setupID)
	if err != nil {
		return nil, err
	}
	snapshot := &InventorySnapshot{
		Source:             "account_manifest",
		Completeness:       InventoryCompletenessComplete,
		NetworkID:          networkID,
		ObservedRowCount:   len(discovered),
		DiscoveredAccounts: discovered,
	}
	if len(discovered) == 0 {
		snapshot.SelectedSetupIDs = []SetupID{}
	} else {
		snapshot.SelectedSetupIDs = []SetupID{SetupID(setupID)}
	}
	summary, runErr := runPlannedSyncFromSnapshot(ctx, cfg, client, snapshot, cloudAccounts)
	if summary != nil {
		summary.SafetyWarnings = append(summary.SafetyWarnings, warnings...)
	}
	return summary, runErr
}

func inspectManifestInventoryShape(
	ctx context.Context,
	client *api.Client,
	cfg Config,
	setupID string,
	manifest []AWSOrganizationAccount,
	cloudAccounts []api.CloudAccount,
) []SafetyWarning {
	query, queryID, parameters := queryInputs(cfg)
	queryResult, err := client.QueryAWSAccountsWithMetadata(
		ctx,
		cfg.NetworkID,
		cfg.SnapshotID,
		query,
		queryID,
		parameters,
		[]string{setupID},
	)
	if err != nil {
		return []SafetyWarning{{
			Code: "manifest_nqe_shape_check_unavailable",
			Message: fmt.Sprintf(
				"WARNING: could not compare the reviewed manifest with current NQE-observed inventory: %v. This does not block sync-accounts; independently confirm the manifest is authoritative and was not generated from NQE output.",
				err,
			),
		}}
	}
	nqeSnapshot, err := parseNQESnapshotFromMapsWithOptions(
		queryResult.Items,
		nqeParseOptionsFromQueryResult(queryResult, cfg.AllowMalformedRows),
	)
	if err != nil {
		return []SafetyWarning{{
			Code: "manifest_nqe_shape_check_unavailable",
			Message: fmt.Sprintf(
				"WARNING: could not interpret current NQE-observed inventory for the manifest safeguard: %v. This does not block sync-accounts; independently confirm the manifest is authoritative and was not generated from NQE output.",
				err,
			),
		}}
	}

	manifestIDs := makeStringSet(len(manifest))
	for _, account := range manifest {
		manifestIDs[strings.TrimSpace(account.ID)] = struct{}{}
	}
	nqeIDs := makeStringSet(len(nqeSnapshot.DiscoveredAccounts))
	for _, account := range nqeSnapshot.DiscoveredAccounts {
		if !account.SetupID.IsZero() && account.SetupID.String() != setupID {
			continue
		}
		nqeIDs[account.AccountID.String()] = struct{}{}
	}
	configuredIDs := makeStringSet(0)
	for _, cloudAccount := range cloudAccounts {
		if strings.TrimSpace(cloudAccount.Name) != setupID {
			continue
		}
		configuredIDs = makeStringSet(len(cloudAccount.AssumeRoleInfos))
		for _, account := range cloudAccount.AssumeRoleInfos {
			if accountID := assumeRoleAccountID(account); accountID != "" {
				configuredIDs[accountID] = struct{}{}
			}
		}
		break
	}

	similarity := setJaccardSimilarity(manifestIDs, nqeIDs)
	configuredDifference := setDifferenceFraction(manifestIDs, configuredIDs)
	if len(manifestIDs) == 0 || len(nqeIDs) == 0 || len(configuredIDs) == 0 ||
		similarity < manifestNQESimilarityThreshold ||
		configuredDifference < manifestConfiguredDifferenceThreshold {
		return nil
	}
	return []SafetyWarning{{
		Code: "manifest_matches_nqe_observation",
		Message: fmt.Sprintf(
			"WARNING: the reviewed manifest account set matches current NQE-observed inventory by %.2f%% while differing from configured membership by %.2f%%. This is the signature of an NQE-derived manifest; NQE is observed and potentially partial, so confirm the manifest came from an independent authoritative source. This warning does not block the operation because a legitimate manifest can coincidentally match NQE.",
			similarity*100,
			configuredDifference*100,
		),
	}}
}

func makeStringSet(capacity int) map[string]struct{} {
	return make(map[string]struct{}, capacity)
}

func setJaccardSimilarity(left, right map[string]struct{}) float64 {
	union := make(map[string]struct{}, len(left)+len(right))
	intersection := 0
	for value := range left {
		union[value] = struct{}{}
		if _, ok := right[value]; ok {
			intersection++
		}
	}
	for value := range right {
		union[value] = struct{}{}
	}
	if len(union) == 0 {
		return 1
	}
	return float64(intersection) / float64(len(union))
}

func setDifferenceFraction(candidate, configured map[string]struct{}) float64 {
	if len(configured) == 0 {
		return 0
	}
	return 1 - setJaccardSimilarity(candidate, configured)
}
