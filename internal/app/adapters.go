package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

var nqeSetupIDColumns = []string{"Cloud Setup ID", "Setup ID", "Cloud Account Setup ID", "Cloud Account Setup"}

type externalIDBySetupAssignments map[SetupID]map[AccountID]string

type parseNQESnapshotOptions struct {
	AllowMalformedRows bool
	Completeness       InventoryCompleteness
	CompletenessReason string
	PageLimit          int
}

func adaptExternalIDAssignments(assignments externalIDAssignments) (externalIDBySetupAssignments, error) {
	if len(assignments) == 0 {
		return nil, nil
	}

	converted := make(map[SetupID]map[AccountID]string, len(assignments))
	for setupIDRaw, byAccount := range assignments {
		setupID, err := NewSetupID(setupIDRaw)
		if err != nil {
			return nil, fmt.Errorf("external ID assignment has invalid setup ID %q: %w", setupIDRaw, err)
		}
		if _, exists := converted[setupID]; exists {
			return nil, fmt.Errorf("external ID file contains duplicate setup %q", setupID)
		}
		converted[setupID] = make(map[AccountID]string, len(byAccount))
		for rawAccountID, externalID := range byAccount {
			accountID, err := NewAccountID(rawAccountID)
			if err != nil {
				return nil, fmt.Errorf("external ID assignment for setup %q has invalid AWS account ID %q: %w", setupID, rawAccountID, err)
			}
			if _, exists := converted[setupID][accountID]; exists {
				return nil, fmt.Errorf("external ID file contains duplicate setup/account entry %s/%s", setupID, accountID)
			}
			converted[setupID][accountID] = strings.TrimSpace(externalID)
		}
	}
	return converted, nil
}

// parseNQESnapshotFromMaps adapts rows with no pagination metadata available.
// NQE cannot prove its result is complete, so completeness defaults to unknown
// and absence-based removal is refused downstream. Callers holding pagination
// metadata must use parseNQESnapshotFromMapsWithOptions instead.
func parseNQESnapshotFromMaps(items []map[string]any) (*InventorySnapshot, error) {
	return parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		Completeness: InventoryCompletenessUnknown,
	})
}

func parseNQESnapshotFromMapsWithOptions(items []map[string]any, options parseNQESnapshotOptions) (*InventorySnapshot, error) {
	snapshot := &InventorySnapshot{
		Source:             "nqe",
		ObservedRowCount:   len(items),
		PageLimit:          options.PageLimit,
		Completeness:       options.Completeness,
		CompletenessReason: strings.TrimSpace(options.CompletenessReason),
	}
	seenBySetup := make(map[SetupID]map[AccountID]bool)
	accountOwners := make(map[AccountID]SetupID)
	selectedSetups := make(map[SetupID]struct{})
	for rowIndex, item := range items {
		r := rowIndex + 1
		setupID, err := extractNQESetupID(item, r)
		if err != nil {
			return nil, err
		}
		accountID, err := extractNQEAccountID(item, r)
		if err != nil {
			if options.AllowMalformedRows && isMalformedNQEAccountIDError(err) {
				snapshot.SkippedRows = append(snapshot.SkippedRows, MalformedNQERowSummary{
					Row:       r,
					SetupID:   setupID.String(),
					AccountID: rawNQEAccountID(item),
					Reason:    err.Error(),
				})
				snapshot.IgnoredAccounts = append(snapshot.IgnoredAccounts, AccountSummary{AccountID: rawNQEAccountID(item)})
				snapshot.Completeness = InventoryCompletenessLikelyIncomplete
				if snapshot.CompletenessReason == "" {
					snapshot.CompletenessReason = "--allow-malformed-rows skipped malformed NQE rows, so the inventory is incomplete"
				}
				continue
			}
			return nil, err
		}
		accountName, err := extractOptionalString(item, "Cloud Account Name", r)
		if err != nil {
			return nil, err
		}
		if accountName == "" {
			accountName = accountID.String()
		}
		if _, exists := accountOwners[accountID]; exists && accountOwners[accountID] != setupID {
			return nil, fmt.Errorf("NQE row %d has account %s in setup %s but that account already appears in setup %s", r, accountID, setupID, accountOwners[accountID])
		}
		if _, ok := seenBySetup[setupID]; !ok {
			seenBySetup[setupID] = make(map[AccountID]bool)
		}
		if seenBySetup[setupID][accountID] {
			return nil, fmt.Errorf("NQE row %d duplicates account %s in setup %s", r, accountID, setupID)
		}
		seenBySetup[setupID][accountID] = true
		accountOwners[accountID] = setupID
		if !setupID.IsZero() {
			selectedSetups[setupID] = struct{}{}
		}

		collectedSet := false
		collected := false
		if raw, ok := item["Collected?"]; ok {
			collectedSet = true
			parsed, err := parseCollectedFlag(raw)
			if err != nil {
				return nil, fmt.Errorf("NQE row %d has invalid Collected? value: %w", r, err)
			}
			collected = parsed
		}
		hasOrgIDs, err := parseHasOrgUnitIDs(item["Organizational Unit IDs"])
		if err != nil {
			return nil, fmt.Errorf("NQE row %d has invalid Organizational Unit IDs: %w", r, err)
		}
		lifecycle, err := parseLifecycle(item["Account Lifecycle"], r)
		if err != nil {
			return nil, err
		}
		snapshot.DiscoveredAccounts = append(snapshot.DiscoveredAccounts, DiscoveredAccount{
			SetupID:             setupID,
			AccountID:           accountID,
			AccountName:         accountName,
			Lifecycle:           lifecycle,
			CollectedSet:        collectedSet,
			Collected:           collected,
			HasOrganizationalID: hasOrgIDs,
			Membership:          MembershipPreserve,
		})
	}
	if len(selectedSetups) > 0 {
		snapshot.SelectedSetupIDs = make([]SetupID, 0, len(selectedSetups))
		for setupID := range selectedSetups {
			snapshot.SelectedSetupIDs = append(snapshot.SelectedSetupIDs, setupID)
		}
		sort.Slice(snapshot.SelectedSetupIDs, func(i, j int) bool {
			return snapshot.SelectedSetupIDs[i] < snapshot.SelectedSetupIDs[j]
		})
	}
	return snapshot, nil
}

func isMalformedNQEAccountIDError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "Cloud Account ID") ||
		strings.Contains(message, "invalid AWS account ID")
}

func rawNQEAccountID(item map[string]any) string {
	raw, ok := item["Cloud Account ID"]
	if !ok || raw == nil {
		return ""
	}
	if value, ok := raw.(string); ok {
		return strings.TrimSpace(value)
	}
	return fmt.Sprintf("%v", raw)
}

func extractNQESetupID(item map[string]any, row int) (SetupID, error) {
	for _, key := range nqeSetupIDColumns {
		raw, ok := item[key]
		if !ok {
			continue
		}
		value, err := extractString(raw)
		if err != nil {
			return "", fmt.Errorf("NQE row %d has non-string setup-id value in %s", row, key)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return "", nil
		}
		setupID, err := NewSetupID(trimmed)
		if err != nil {
			return "", fmt.Errorf("NQE row %d has invalid setup ID %q: %w", row, value, err)
		}
		return setupID, nil
	}
	return "", nil
}

func extractNQEAccountID(item map[string]any, row int) (AccountID, error) {
	raw, ok := item["Cloud Account ID"]
	if !ok {
		return "", fmt.Errorf("NQE row %d is missing Cloud Account ID", row)
	}
	text, err := extractString(raw)
	if err != nil {
		return "", fmt.Errorf("NQE row %d has non-string Cloud Account ID", row)
	}
	accountID, err := NewAccountID(text)
	if err != nil {
		return "", err
	}
	return accountID, nil
}

func extractOptionalString(item map[string]any, column string, row int) (string, error) {
	raw, ok := item[column]
	if !ok {
		return "", nil
	}
	value, err := extractString(raw)
	if err != nil {
		return "", fmt.Errorf("NQE row %d has non-string value for %s", row, column)
	}
	return strings.TrimSpace(value), nil
}

func extractString(value any) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("value is not string")
	}
	return strings.TrimSpace(s), nil
}

func parseCollectedFlag(value any) (bool, error) {
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "1":
			return true, nil
		case "false", "no", "0":
			return false, nil
		}
	}
	return false, fmt.Errorf("expected boolean or true/false/yes/no")
}

func parseHasOrgUnitIDs(value any) (bool, error) {
	switch typed := value.(type) {
	case nil:
		return false, nil
	case []any:
		return len(typed) > 0, nil
	case []string:
		return len(typed) > 0, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" || trimmed == "[]" {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("expected Organizational Unit IDs to be an array or string")
	}
}

func parseLifecycle(raw any, row int) (AccountLifecycle, error) {
	if raw == nil {
		return AccountLifecycleUnknown, nil
	}
	value, err := extractString(raw)
	if err != nil {
		return AccountLifecycleUnknown, fmt.Errorf("NQE row %d has non-string Account Lifecycle", row)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return AccountLifecycleUnknown, nil
	}
	switch AccountLifecycle(value) {
	case AccountLifecycleActive, AccountLifecycleSuspended, AccountLifecycleClosing, AccountLifecycleClosed:
		return AccountLifecycle(value), nil
	default:
		return AccountLifecycleUnknown, fmt.Errorf("NQE row %d has invalid lifecycle %q", row, value)
	}
}

func adaptManifestAccountsToSetupRows(accounts []AWSOrganizationAccount, setupID string) ([]DiscoveredAccount, error) {
	canonicalSetup, err := NewSetupID(setupID)
	if err != nil {
		return nil, err
	}
	result := make([]DiscoveredAccount, 0, len(accounts))
	seen := make(map[AccountID]bool, len(accounts))
	for _, account := range accounts {
		accountID, err := NewAccountID(account.ID)
		if err != nil {
			return nil, fmt.Errorf("accounts file entry for setup %s has invalid AWS account ID %q; expected exactly 12 digits", canonicalSetup, account.ID)
		}
		if seen[accountID] {
			return nil, fmt.Errorf("accounts file contains duplicate AWS account ID %s", accountID)
		}
		seen[accountID] = true
		name := strings.TrimSpace(account.Name)
		if name == "" {
			name = accountID.String()
		}
		result = append(result, DiscoveredAccount{SetupID: canonicalSetup, AccountID: accountID, AccountName: name})
	}
	return result, nil
}

func parseCloudSetupAccountInfo(info api.AssumeRoleInfo, setupID SetupID, row int) (AccountID, RoleARN, error) {
	var accountID AccountID
	var roleARN RoleARN
	rawRole := strings.TrimSpace(info.RoleArn)
	hasRoleARN := rawRole != ""
	if rawRole != "" {
		parsedRole, err := ParseRoleARN(rawRole)
		if err != nil {
			return "", RoleARN{}, fmt.Errorf("setup %s row %d has invalid role ARN %q: %w", setupID, row, rawRole, err)
		}
		roleARN = parsedRole
	}
	if strings.TrimSpace(info.AccountID) != "" {
		id, err := NewAccountID(info.AccountID)
		if err != nil {
			return "", RoleARN{}, fmt.Errorf("setup %s row %d has invalid AWS account ID %q; expected exactly 12 digits", setupID, row, info.AccountID)
		}
		accountID = id
	}
	if accountID.IsZero() {
		if !hasRoleARN {
			return "", RoleARN{}, fmt.Errorf("setup %s row %d has no account identity", setupID, row)
		}
		accountID = roleARN.AccountID()
	}
	if hasRoleARN && strings.TrimSpace(info.AccountID) != "" {
		if roleAccount := roleARN.AccountID().String(); roleAccount != accountID.String() {
			return "", RoleARN{}, fmt.Errorf("setup %s row %d has account ID %s that disagrees with role ARN account %s", setupID, row, accountID, roleAccount)
		}
	}
	return accountID, roleARN, nil
}

type cloudSetupMetadata struct {
	setupID             SetupID
	cloudType           string
	proxyServerID       string
	regionToProxyServer map[string]string
	regions             map[string]api.RegionMeta
	assumeRoleInfos     []api.AssumeRoleInfo
}

func adaptCloudAccountsBySetupID(cloudAccounts []api.CloudAccount, setupIDs []string) (map[SetupID]cloudSetupMetadata, error) {
	allowed := setupIDSet(setupIDs)
	result := make(map[SetupID]cloudSetupMetadata, len(cloudAccounts))
	seenAccount := make(map[SetupID]map[AccountID]bool)
	accountOwners := make(map[AccountID]SetupID)
	for _, account := range cloudAccounts {
		accountType := strings.ToUpper(strings.TrimSpace(account.Type))
		if accountType != "" && accountType != "AWS" {
			continue
		}
		setupID, err := NewSetupID(account.Name)
		if err != nil {
			continue
		}
		if len(allowed) > 0 && !allowed[setupID.String()] {
			continue
		}
		if _, ok := result[setupID]; ok {
			return nil, fmt.Errorf("forward setup list contains duplicate setup-id %s", setupID)
		}
		if account.ProxyServerID != "" {
			account.ProxyServerID = strings.TrimSpace(account.ProxyServerID)
		}
		normalizedRegions := map[string]string{}
		for region, proxy := range account.RegionToProxyServerID {
			region = strings.TrimSpace(region)
			proxy = strings.TrimSpace(proxy)
			if region != "" && proxy != "" {
				normalizedRegions[region] = proxy
			}
		}
		state := cloudSetupMetadata{
			setupID:             setupID,
			cloudType:           strings.TrimSpace(account.Type),
			proxyServerID:       strings.TrimSpace(account.ProxyServerID),
			regionToProxyServer: normalizedRegions,
			regions:             account.Regions,
		}
		seen := make(map[AccountID]bool, len(account.AssumeRoleInfos))
		for i, info := range account.AssumeRoleInfos {
			accountID, _, err := parseCloudSetupAccountInfo(info, setupID, i+1)
			if err != nil {
				return nil, err
			}
			if owner, exists := accountOwners[accountID]; exists && owner != setupID {
				return nil, fmt.Errorf("forward setup %s row %d has account %s also configured in setup %s", setupID, i+1, accountID, owner)
			}
			if seen[accountID] {
				return nil, fmt.Errorf("setup %s has duplicate account %s", setupID, accountID)
			}
			seen[accountID] = true
			accountOwners[accountID] = setupID
		}
		seenAccount[setupID] = seen
		state.assumeRoleInfos = append(state.assumeRoleInfos, account.AssumeRoleInfos...)
		result[setupID] = state
	}
	return result, nil
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func SetupIDsFromSnapshot(snapshot *InventorySnapshot) []string {
	result := make([]string, 0, len(snapshot.SelectedSetupIDs))
	for _, setupID := range snapshot.SelectedSetupIDs {
		result = append(result, setupID.String())
	}
	sort.Strings(result)
	return result
}

func adaptCurrentSetup(meta cloudSetupMetadata) (CurrentSetup, error) {
	current := CurrentSetup{
		SetupID: meta.setupID,
		Metadata: SetupMetadata{
			CloudType:           strings.TrimSpace(meta.cloudType),
			ProxyServerID:       strings.TrimSpace(meta.proxyServerID),
			RegionToProxyServer: stringMap(meta.regionToProxyServer),
			Regions:             make(map[string]int64, len(meta.regions)),
		},
		Accounts: make([]SetupAccount, 0, len(meta.assumeRoleInfos)),
	}
	for region, regionMeta := range meta.regions {
		current.Metadata.Regions[region] = regionMeta.TestInstant
	}
	for row, info := range meta.assumeRoleInfos {
		accountID, roleARN, err := parseCloudSetupAccountInfo(info, meta.setupID, row+1)
		if err != nil {
			return CurrentSetup{}, err
		}
		accountName := strings.TrimSpace(info.AccountName)
		if accountName == "" {
			accountName = accountID.String()
		}
		current.Accounts = append(current.Accounts, SetupAccount{
			AccountID:   accountID,
			AccountName: accountName,
			RoleARN:     roleARN,
			ExternalID:  strings.TrimSpace(info.ExternalID),
			Enabled:     info.Enabled,
		})
	}
	return current, nil
}

func patchPayloadFromDesired(desired DesiredSetup) api.PatchPayload {
	payload := api.PatchPayload{
		Type:                  desired.Metadata.CloudType,
		Name:                  desired.SetupID.String(),
		Regions:               cloneInt64Map(desired.Metadata.Regions),
		RegionToProxyServerID: cloneStringMap(desired.Metadata.RegionToProxyServer),
		AssumeRoleInfos:       make([]api.AssumeRoleInfo, 0, len(desired.Accounts)),
	}
	if desired.Metadata.ProxyServerID != "" {
		payload.ProxyServerID = desired.Metadata.ProxyServerID
	}
	for _, account := range desired.Accounts {
		payload.AssumeRoleInfos = append(payload.AssumeRoleInfos, api.AssumeRoleInfo{
			AccountID:   account.AccountID.String(),
			AccountName: account.AccountName,
			RoleArn:     account.RoleARN.String(),
			ExternalID:  account.ExternalID,
			Enabled:     account.Enabled,
		})
	}
	return payload
}
