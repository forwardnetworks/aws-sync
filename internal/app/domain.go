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

func (c InventoryCompleteness) Proven() bool {
	return c == InventoryCompletenessComplete
}

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
	PageLimit          int
	Completeness       InventoryCompleteness
	CompletenessReason string
	DiscoveredAccounts []DiscoveredAccount
	IgnoredAccounts    []AccountSummary
	SkippedRows        []MalformedNQERowSummary
	CompleteIndicator  bool
}

type MalformedNQERowSummary struct {
	Row       int    `json:"row"`
	SetupID   string `json:"setup_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Reason    string `json:"reason"`
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

// SetupAccount is the typed account state used by the reconciliation engine.
type SetupAccount struct {
	AccountID   AccountID
	AccountName string
	RoleARN     RoleARN
	ExternalID  string
	Enabled     bool
}

// SetupMetadata contains the setup-level fields controlled by reconciliation.
type SetupMetadata struct {
	CloudType           string
	ProxyServerID       string
	RegionToProxyServer map[string]string
	Regions             map[string]int64
}

// CurrentSetup is the typed Forward state supplied to ComputeDesired.
type CurrentSetup struct {
	SetupID  SetupID
	Metadata SetupMetadata
	Accounts []SetupAccount
}

// DesiredSetup is the immutable target produced by ComputeDesired.
type DesiredSetup struct {
	SetupID  SetupID
	Metadata SetupMetadata
	Accounts []SetupAccount
}

// ReconcilePolicyKind is the tag identifying how inventory affects membership.
type ReconcilePolicyKind string

const (
	Additive          ReconcilePolicyKind = "Additive"
	CompleteInventory ReconcilePolicyKind = "CompleteInventory"
)

// OrganizationEvidencePolicy records how a policy treats missing NQE
// Organizations evidence without reintroducing interacting CLI booleans.
type OrganizationEvidencePolicy string

const (
	RequireOrganizationEvidence      OrganizationEvidencePolicy = "RequireOrganizationEvidence"
	AllowMissingOrganizationEvidence OrganizationEvidencePolicy = "AllowMissingOrganizationEvidence"
	ReviewedAuthoritativeInventory   OrganizationEvidencePolicy = "ReviewedAuthoritativeInventory"
)

// ReconcilePolicy is a tagged reconciliation policy. PlanningInstant is
// mandatory: ComputeDesired never consults a clock or supplies a fallback.
type ReconcilePolicy struct {
	Kind                 ReconcilePolicyKind
	PlanningInstant      time.Time
	OrganizationEvidence OrganizationEvidencePolicy
	DefaultRoleName      string
	UniformExternalID    *string
	ExternalIDByAccount  map[AccountID]string
}

// ChangeKind enumerates field-level changes emitted by ComputeDesired.
type ChangeKind string

const (
	ChangeAdd              ChangeKind = "Add"
	ChangeEnable           ChangeKind = "Enable"
	ChangeDisable          ChangeKind = "Disable"
	ChangeRemove           ChangeKind = "Remove"
	ChangeRename           ChangeKind = "Rename"
	ChangeRotateExternalID ChangeKind = "RotateExternalID"
	ChangeRole             ChangeKind = "ChangeRole"
)

// AccountChange contains the before/after account state for one field-level
// classification. Before is nil for Add and After is nil for Remove.
type AccountChange struct {
	AccountID AccountID
	Before    *SetupAccount
	After     *SetupAccount
}

// SetupMetadataChange classifies a setup-level field change.
type SetupMetadataChange struct {
	Field  string
	Before any
	After  any
}

// ChangeSet is the field-level diff between CurrentSetup and DesiredSetup.
// One account may appear in more than one field slice.
type ChangeSet struct {
	Add              []AccountChange
	Enable           []AccountChange
	Disable          []AccountChange
	Remove           []AccountChange
	Rename           []AccountChange
	RotateExternalID []AccountChange
	ChangeRole       []AccountChange
	SetupMetadata    []SetupMetadataChange
}

func (c ChangeSet) Empty() bool {
	return len(c.Add) == 0 &&
		len(c.Enable) == 0 &&
		len(c.Disable) == 0 &&
		len(c.Remove) == 0 &&
		len(c.Rename) == 0 &&
		len(c.RotateExternalID) == 0 &&
		len(c.ChangeRole) == 0 &&
		len(c.SetupMetadata) == 0
}
