package app

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ComputeDesired is the pure desired-state and diff engine. It has no clock or
// I/O fallback: callers must supply every input, including PlanningInstant.
func ComputeDesired(current CurrentSetup, snapshot InventorySnapshot, policy ReconcilePolicy) (DesiredSetup, ChangeSet, error) {
	if current.SetupID.IsZero() {
		return DesiredSetup{}, ChangeSet{}, fmt.Errorf("current setup ID is required")
	}
	if policy.PlanningInstant.IsZero() {
		return DesiredSetup{}, ChangeSet{}, fmt.Errorf("reconcile policy planning instant is required")
	}
	switch policy.Kind {
	case Additive, CompleteInventory, ExplicitOperations:
	default:
		return DesiredSetup{}, ChangeSet{}, fmt.Errorf("invalid reconcile policy kind %q", policy.Kind)
	}
	if policy.Kind == CompleteInventory && !snapshot.Completeness.Proven() {
		return DesiredSetup{}, ChangeSet{}, incompleteInventoryPolicyError(snapshot)
	}

	currentByID, err := indexSetupAccounts(current.Accounts, "current setup")
	if err != nil {
		return DesiredSetup{}, ChangeSet{}, err
	}
	discoveredByID, err := discoveredAccountsForSetup(snapshot.DiscoveredAccounts, current.SetupID)
	if err != nil {
		return DesiredSetup{}, ChangeSet{}, err
	}

	targetMembership := make(map[AccountID]DesiredMembership)
	targetNames := make(map[AccountID]string)
	switch policy.Kind {
	case Additive:
		for id, account := range discoveredByID {
			targetMembership[id] = additiveMembership(account.Membership)
			targetNames[id] = discoveredAccountName(account)
		}
		for id, account := range currentByID {
			if _, exists := targetMembership[id]; exists {
				continue
			}
			targetMembership[id] = MembershipPresentEnabled
			targetNames[id] = accountName(account)
		}
	case CompleteInventory:
		for id, account := range discoveredByID {
			if account.Membership == MembershipExplicitlyRemove {
				continue
			}
			targetMembership[id] = inventoryMembership(account.Membership)
			targetNames[id] = discoveredAccountName(account)
		}
	case ExplicitOperations:
		for id, account := range currentByID {
			membership := MembershipPresentDisabled
			if account.Enabled {
				membership = MembershipPresentEnabled
			}
			targetMembership[id] = membership
			targetNames[id] = accountName(account)
		}
		if err := applyExplicitMembershipOperations(targetMembership, targetNames, discoveredByID, policy.Operations); err != nil {
			return DesiredSetup{}, ChangeSet{}, err
		}
	}

	desiredAccounts, err := materializeDesiredAccounts(currentByID, targetMembership, targetNames, policy)
	if err != nil {
		return DesiredSetup{}, ChangeSet{}, err
	}
	if policy.Kind == ExplicitOperations {
		if err := applyExplicitFieldOperations(desiredAccounts, policy.Operations); err != nil {
			return DesiredSetup{}, ChangeSet{}, err
		}
	}

	desired := DesiredSetup{
		SetupID: current.SetupID,
		Metadata: SetupMetadata{
			CloudType:           "AWS",
			ProxyServerID:       strings.TrimSpace(current.Metadata.ProxyServerID),
			RegionToProxyServer: cloneStringMap(current.Metadata.RegionToProxyServer),
			Regions:             desiredRegions(current.Metadata.Regions, policy.PlanningInstant.UnixMilli()),
		},
		Accounts: sortedSetupAccounts(desiredAccounts),
	}
	changes := diffSetup(current, desired)
	return desired, changes, nil
}

func incompleteInventoryPolicyError(snapshot InventorySnapshot) error {
	reason := strings.TrimSpace(snapshot.CompletenessReason)
	if reason == "" {
		reason = "inventory completeness is unproven"
	}
	return fmt.Errorf(
		"refusing absence-based removals because inventory completeness is unproven: %s; observed_count=%d PageLimit=%d. Fix the NQE query/data and rerun --prune-missing only after a proven complete inventory, or rerun without --prune-missing to add/re-enable only",
		reason,
		snapshot.ObservedRowCount,
		snapshot.PageLimit,
	)
}

func indexSetupAccounts(accounts []SetupAccount, source string) (map[AccountID]SetupAccount, error) {
	result := make(map[AccountID]SetupAccount, len(accounts))
	for _, account := range accounts {
		if account.AccountID.IsZero() {
			return nil, fmt.Errorf("%s contains an account with no ID", source)
		}
		if !account.RoleARN.AccountID().IsZero() && account.RoleARN.AccountID() != account.AccountID {
			return nil, fmt.Errorf("%s account %s disagrees with role ARN account %s", source, account.AccountID, account.RoleARN.AccountID())
		}
		if _, exists := result[account.AccountID]; exists {
			return nil, fmt.Errorf("%s contains duplicate account %s", source, account.AccountID)
		}
		result[account.AccountID] = cloneSetupAccount(account)
	}
	return result, nil
}

func discoveredAccountsForSetup(accounts []DiscoveredAccount, setupID SetupID) (map[AccountID]DiscoveredAccount, error) {
	result := make(map[AccountID]DiscoveredAccount)
	for _, account := range accounts {
		if !account.SetupID.IsZero() && account.SetupID != setupID {
			continue
		}
		if account.AccountID.IsZero() {
			return nil, fmt.Errorf("inventory for setup %s contains an account with no ID", setupID)
		}
		if _, exists := result[account.AccountID]; exists {
			return nil, fmt.Errorf("inventory for setup %s contains duplicate account %s", setupID, account.AccountID)
		}
		result[account.AccountID] = account
	}
	return result, nil
}

func additiveMembership(membership DesiredMembership) DesiredMembership {
	return MembershipPresentEnabled
}

func inventoryMembership(membership DesiredMembership) DesiredMembership {
	if membership == MembershipPresentDisabled {
		return MembershipPresentDisabled
	}
	return MembershipPresentEnabled
}

func discoveredAccountName(account DiscoveredAccount) string {
	name := strings.TrimSpace(account.AccountName)
	if name == "" {
		return account.AccountID.String()
	}
	return name
}

func accountName(account SetupAccount) string {
	name := strings.TrimSpace(account.AccountName)
	if name == "" {
		return account.AccountID.String()
	}
	return name
}

func applyExplicitMembershipOperations(
	membership map[AccountID]DesiredMembership,
	names map[AccountID]string,
	discovered map[AccountID]DiscoveredAccount,
	operations []ExplicitAccountOperation,
) error {
	for _, operation := range operations {
		if operation.AccountID.IsZero() {
			return fmt.Errorf("explicit %s operation has no account ID", operation.Kind)
		}
		switch operation.Kind {
		case ChangeAdd:
			account, ok := discovered[operation.AccountID]
			if !ok {
				return fmt.Errorf("explicit Add for account %s requires a matching inventory row", operation.AccountID)
			}
			membership[operation.AccountID] = inventoryMembership(account.Membership)
			names[operation.AccountID] = discoveredAccountName(account)
		case ChangeEnable:
			if _, ok := membership[operation.AccountID]; !ok {
				return fmt.Errorf("explicit Enable references unknown account %s", operation.AccountID)
			}
			membership[operation.AccountID] = MembershipPresentEnabled
		case ChangeDisable:
			if _, ok := membership[operation.AccountID]; !ok {
				return fmt.Errorf("explicit Disable references unknown account %s", operation.AccountID)
			}
			membership[operation.AccountID] = MembershipPresentDisabled
		case ChangeRemove:
			if _, ok := membership[operation.AccountID]; !ok {
				return fmt.Errorf("explicit Remove references unknown account %s", operation.AccountID)
			}
			delete(membership, operation.AccountID)
			delete(names, operation.AccountID)
		case ChangeRename, ChangeRotateExternalID, ChangeRole:
			if _, ok := membership[operation.AccountID]; !ok {
				return fmt.Errorf("explicit %s references unknown account %s", operation.Kind, operation.AccountID)
			}
		default:
			return fmt.Errorf("unsupported explicit account operation %q", operation.Kind)
		}
	}
	return nil
}

func materializeDesiredAccounts(
	current map[AccountID]SetupAccount,
	membership map[AccountID]DesiredMembership,
	names map[AccountID]string,
	policy ReconcilePolicy,
) (map[AccountID]SetupAccount, error) {
	roleName := strings.TrimSpace(policy.DefaultRoleName)
	partition, err := currentPartition(current)
	if err != nil {
		return nil, err
	}
	if len(membership) > 0 && roleName == "" {
		return nil, fmt.Errorf("unable to determine role ARN name")
	}

	currentExternalIDs := make(map[AccountID]string, len(current))
	currentExternalID := ""
	currentExternalIDConsistent := true
	firstExternalID := true
	for id, account := range current {
		value := strings.TrimSpace(account.ExternalID)
		currentExternalIDs[id] = value
		if firstExternalID {
			currentExternalID = value
			firstExternalID = false
		} else if value != currentExternalID {
			currentExternalIDConsistent = false
		}
	}

	for id := range policy.ExternalIDByAccount {
		if _, exists := membership[id]; !exists {
			return nil, fmt.Errorf("external ID file contains account(s) not present in the discovered inventory: %s", id)
		}
	}

	result := make(map[AccountID]SetupAccount, len(membership))
	missingAssignments := make([]string, 0)
	for id, desiredMembership := range membership {
		roleARN, err := NewRoleARN(id, partition, roleName)
		if err != nil {
			return nil, err
		}
		externalID := ""
		switch {
		case policy.UniformExternalID != nil:
			externalID = strings.TrimSpace(*policy.UniformExternalID)
		case hasExternalIDAssignment(policy.ExternalIDByAccount, id):
			externalID = strings.TrimSpace(policy.ExternalIDByAccount[id])
		case currentExternalIDs[id] != "":
			externalID = currentExternalIDs[id]
		case currentAccountHasExternalID(current, id):
			externalID = ""
		case currentExternalIDConsistent:
			externalID = currentExternalID
		default:
			missingAssignments = append(missingAssignments, id.String())
		}
		result[id] = SetupAccount{
			AccountID:   id,
			AccountName: strings.TrimSpace(names[id]),
			RoleARN:     roleARN,
			ExternalID:  externalID,
			Enabled:     desiredMembership != MembershipPresentDisabled,
		}
	}
	if len(missingAssignments) > 0 {
		sort.Strings(missingAssignments)
		return nil, fmt.Errorf(
			"existing accounts use mixed External IDs; provide --external-id-file assignments for each new account: %s",
			strings.Join(missingAssignments, ", "),
		)
	}
	return result, nil
}

func currentPartition(current map[AccountID]SetupAccount) (Partition, error) {
	var partition Partition
	for _, account := range current {
		if account.RoleARN.String() == "" {
			continue
		}
		if partition == "" {
			partition = account.RoleARN.Partition()
			continue
		}
		if partition != account.RoleARN.Partition() {
			return "", fmt.Errorf("current setup contains mixed role ARN partitions")
		}
	}
	if partition == "" {
		return PartitionAWS, nil
	}
	return partition, nil
}

func hasExternalIDAssignment(assignments map[AccountID]string, id AccountID) bool {
	_, ok := assignments[id]
	return ok
}

func currentAccountHasExternalID(current map[AccountID]SetupAccount, id AccountID) bool {
	_, ok := current[id]
	return ok
}

func applyExplicitFieldOperations(accounts map[AccountID]SetupAccount, operations []ExplicitAccountOperation) error {
	for _, operation := range operations {
		account, exists := accounts[operation.AccountID]
		switch operation.Kind {
		case ChangeRename:
			if !exists {
				return fmt.Errorf("explicit Rename references unknown account %s", operation.AccountID)
			}
			account.AccountName = strings.TrimSpace(operation.Value)
			if account.AccountName == "" {
				return fmt.Errorf("explicit Rename for account %s requires a non-empty name", operation.AccountID)
			}
			accounts[operation.AccountID] = account
		case ChangeRotateExternalID:
			if !exists {
				return fmt.Errorf("explicit RotateExternalID references unknown account %s", operation.AccountID)
			}
			account.ExternalID = strings.TrimSpace(operation.Value)
			accounts[operation.AccountID] = account
		case ChangeRole:
			if !exists {
				return fmt.Errorf("explicit ChangeRole references unknown account %s", operation.AccountID)
			}
			roleARN, err := ParseRoleARN(operation.Value)
			if err != nil {
				return err
			}
			if roleARN.AccountID() != operation.AccountID {
				return fmt.Errorf("explicit ChangeRole account %s disagrees with role ARN account %s", operation.AccountID, roleARN.AccountID())
			}
			account.RoleARN = roleARN
			accounts[operation.AccountID] = account
		}
	}
	return nil
}

func desiredRegions(current map[string]int64, planningInstant int64) map[string]int64 {
	result := make(map[string]int64, len(current))
	for region, testInstant := range current {
		if testInstant == 0 {
			result[region] = planningInstant
			continue
		}
		result[region] = testInstant
	}
	return result
}

func sortedSetupAccounts(accounts map[AccountID]SetupAccount) []SetupAccount {
	ids := make([]AccountID, 0, len(accounts))
	for id := range accounts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	result := make([]SetupAccount, 0, len(ids))
	for _, id := range ids {
		result = append(result, cloneSetupAccount(accounts[id]))
	}
	return result
}

func diffSetup(current CurrentSetup, desired DesiredSetup) ChangeSet {
	currentByID, _ := indexSetupAccounts(current.Accounts, "current setup")
	desiredByID, _ := indexSetupAccounts(desired.Accounts, "desired setup")
	ids := make([]AccountID, 0, len(currentByID)+len(desiredByID))
	seen := make(map[AccountID]bool, len(currentByID)+len(desiredByID))
	for id := range currentByID {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range desiredByID {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	var changes ChangeSet
	for _, id := range ids {
		before, beforeOK := currentByID[id]
		after, afterOK := desiredByID[id]
		switch {
		case !beforeOK:
			changes.Add = append(changes.Add, accountChange(id, nil, &after))
		case !afterOK:
			changes.Remove = append(changes.Remove, accountChange(id, &before, nil))
		default:
			if !before.Enabled && after.Enabled {
				changes.Enable = append(changes.Enable, accountChange(id, &before, &after))
			}
			if before.Enabled && !after.Enabled {
				changes.Disable = append(changes.Disable, accountChange(id, &before, &after))
			}
			if strings.TrimSpace(before.AccountName) != strings.TrimSpace(after.AccountName) {
				changes.Rename = append(changes.Rename, accountChange(id, &before, &after))
			}
			if strings.TrimSpace(before.ExternalID) != strings.TrimSpace(after.ExternalID) {
				changes.RotateExternalID = append(changes.RotateExternalID, accountChange(id, &before, &after))
			}
			if before.RoleARN.String() != after.RoleARN.String() {
				changes.ChangeRole = append(changes.ChangeRole, accountChange(id, &before, &after))
			}
		}
	}

	if strings.TrimSpace(current.Metadata.CloudType) != strings.TrimSpace(desired.Metadata.CloudType) {
		changes.SetupMetadata = append(changes.SetupMetadata, SetupMetadataChange{
			Field: "cloudType", Before: current.Metadata.CloudType, After: desired.Metadata.CloudType,
		})
	}
	if strings.TrimSpace(current.Metadata.ProxyServerID) != strings.TrimSpace(desired.Metadata.ProxyServerID) {
		changes.SetupMetadata = append(changes.SetupMetadata, SetupMetadataChange{
			Field: "proxyServerId", Before: current.Metadata.ProxyServerID, After: desired.Metadata.ProxyServerID,
		})
	}
	if !reflect.DeepEqual(current.Metadata.RegionToProxyServer, desired.Metadata.RegionToProxyServer) {
		changes.SetupMetadata = append(changes.SetupMetadata, SetupMetadataChange{
			Field:  "regionToProxyServerId",
			Before: cloneStringMap(current.Metadata.RegionToProxyServer),
			After:  cloneStringMap(desired.Metadata.RegionToProxyServer),
		})
	}
	if !reflect.DeepEqual(current.Metadata.Regions, desired.Metadata.Regions) {
		changes.SetupMetadata = append(changes.SetupMetadata, SetupMetadataChange{
			Field: "regions", Before: cloneInt64Map(current.Metadata.Regions), After: cloneInt64Map(desired.Metadata.Regions),
		})
	}
	return changes
}

func accountChange(id AccountID, before, after *SetupAccount) AccountChange {
	change := AccountChange{AccountID: id}
	if before != nil {
		value := cloneSetupAccount(*before)
		change.Before = &value
	}
	if after != nil {
		value := cloneSetupAccount(*after)
		change.After = &value
	}
	return change
}

func cloneSetupAccount(account SetupAccount) SetupAccount {
	return account
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneInt64Map(values map[string]int64) map[string]int64 {
	if values == nil {
		return nil
	}
	result := make(map[string]int64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
