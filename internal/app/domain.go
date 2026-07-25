package app

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// AccountID is a validated AWS account identifier.
type AccountID string

func NewAccountID(value string) (AccountID, error) {
	trimmed := strings.TrimSpace(value)
	if !accountIDPattern.MatchString(trimmed) {
		return "", fmt.Errorf("invalid AWS account ID %q; expected exactly 12 digits", value)
	}
	return AccountID(trimmed), nil
}

func (id AccountID) String() string {
	return string(id)
}

func (id AccountID) IsZero() bool {
	return id == ""
}

// SetupID is a canonicalized setup identifier.
type SetupID string

func NewSetupID(value string) (SetupID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("setup ID is required")
	}
	return SetupID(trimmed), nil
}

func (id SetupID) IsZero() bool {
	return strings.TrimSpace(string(id)) == ""
}

func SetupIDFrom(value string) SetupID {
	return SetupID(strings.TrimSpace(value))
}

func (id SetupID) String() string {
	return strings.TrimSpace(string(id))
}

// Partition enumerates AWS partition values used by IAM ARNs.
type Partition string

const (
	PartitionAWS    Partition = "aws"
	PartitionAWSGov Partition = "aws-us-gov"
	PartitionAWSCN  Partition = "aws-cn"
)

func NewPartition(value string) (Partition, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return PartitionAWS, nil
	}
	switch trimmed {
	case string(PartitionAWS), string(PartitionAWSGov), string(PartitionAWSCN):
		return Partition(trimmed), nil
	default:
		return "", fmt.Errorf("invalid AWS partition %q; expected aws, aws-us-gov, or aws-cn", value)
	}
}

// RoleARN is a validated IAM role ARN.
type RoleARN struct {
	value     string
	partition Partition
	accountID AccountID
	roleName  string
}

func ParseRoleARN(raw string) (RoleARN, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RoleARN{}, fmt.Errorf("invalid IAM role ARN %q", raw)
	}
	parts := strings.Split(raw, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" {
		return RoleARN{}, fmt.Errorf("invalid IAM role ARN %q", raw)
	}
	partition, err := NewPartition(parts[1])
	if err != nil {
		return RoleARN{}, err
	}
	accountID, err := NewAccountID(parts[4])
	if err != nil {
		return RoleARN{}, fmt.Errorf("invalid IAM role ARN %q account component: %w", raw, err)
	}
	rolePath := strings.Join(parts[5:], ":")
	if !strings.HasPrefix(rolePath, "role/") {
		return RoleARN{}, fmt.Errorf("invalid IAM role ARN %q", raw)
	}
	roleName := strings.TrimPrefix(rolePath, "role/")
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return RoleARN{}, fmt.Errorf("invalid IAM role ARN %q", raw)
	}
	return RoleARN{value: raw, partition: partition, accountID: accountID, roleName: roleName}, nil
}

func NewRoleARN(accountID AccountID, partition Partition, roleName string) (RoleARN, error) {
	if accountID.IsZero() {
		return RoleARN{}, fmt.Errorf("account ID is required")
	}
	validatedPartition, err := NewPartition(string(partition))
	if err != nil {
		return RoleARN{}, err
	}
	r := strings.TrimSpace(roleName)
	if r == "" {
		return RoleARN{}, fmt.Errorf("role name is required")
	}
	value := fmt.Sprintf("arn:%s:iam::%s:role/%s", validatedPartition, accountID, r)
	parsed, err := ParseRoleARN(value)
	if err != nil {
		return RoleARN{}, err
	}
	if parsed.AccountID() != accountID {
		return RoleARN{}, fmt.Errorf("account ID mismatch in role ARN: %q vs %q", parsed.AccountID(), accountID)
	}
	return parsed, nil
}

func (r RoleARN) String() string {
	return strings.TrimSpace(r.value)
}

func (r RoleARN) Partition() Partition {
	return r.partition
}

func (r RoleARN) AccountID() AccountID {
	return r.accountID
}

func (r RoleARN) RoleName() string {
	return r.roleName
}

// AccountLifecycle tracks the status of a known account row.
type AccountLifecycle string

const (
	AccountLifecycleActive    AccountLifecycle = "Active"
	AccountLifecycleSuspended AccountLifecycle = "Suspended"
	AccountLifecycleClosing   AccountLifecycle = "Closing"
	AccountLifecycleClosed    AccountLifecycle = "Closed"
	AccountLifecycleUnknown   AccountLifecycle = "Unknown"
)

// DesiredMembership captures expected membership in the target setup.
type DesiredMembership string

const (
	MembershipPreserve         DesiredMembership = "Preserve"
	MembershipPresentEnabled   DesiredMembership = "PresentEnabled"
	MembershipPresentDisabled  DesiredMembership = "PresentDisabled"
	MembershipExplicitlyRemove DesiredMembership = "ExplicitlyRemove"
)

// InventoryCompleteness marks source trust in row completeness.
type InventoryCompleteness int

const (
	InventoryCompletenessUnknown InventoryCompleteness = iota
	InventoryCompletenessLikelyIncomplete
	InventoryCompletenessComplete
)

// InventorySnapshot is a typed snapshot of discovered account inventory.
type InventorySnapshot struct {
	Source             string
	NetworkID          string
	SnapshotID         string
	SnapshotTime       *time.Time
	OrganizationID     string
	SelectedSetupIDs   []SetupID
	ExpectedRowCount   *int
	ObservedRowCount   int
	Completeness       InventoryCompleteness
	DiscoveredAccounts []DiscoveredAccount
	IgnoredAccounts    []AccountSummary
	CompleteIndicator  bool
}

// DiscoveredAccount captures one discovered row in a typed inventory.
type DiscoveredAccount struct {
	SetupID             SetupID
	AccountID           AccountID
	AccountName         string
	Lifecycle           AccountLifecycle
	CollectedSet        bool
	Collected           bool
	HasOrganizationalID bool
	Membership          DesiredMembership
}
