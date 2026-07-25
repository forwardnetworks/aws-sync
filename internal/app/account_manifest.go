package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/forwardnetworks/aws-sync/internal/api"
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
	cfg.AuthoritativeInput = true

	cloudAccounts, err := client.CloudAccounts(ctx, networkID)
	if err != nil {
		return nil, err
	}
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
	return runPlannedSyncFromSnapshot(ctx, cfg, client, snapshot, cloudAccounts)
}
