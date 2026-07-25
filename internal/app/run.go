package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

const DefaultQueryID = "FQ_6d355dca16ed9aae1eb7ad152c7fd13ccdf082fa"

const DefaultQuery = `foreach cloudAccount in network.cloudAccounts
select {
  "Cloud Account Name": cloudAccount.name,
  "Cloud Account ID": cloudAccount.id,
  "Cloud Type": cloudAccount.cloudType,
  "Cloud Setup ID": cloudAccount.cloudSetupId,
  "Organizational Unit IDs": cloudAccount.organizationalUnitIds,
  "Collected?": cloudAccount.collected
}`

const ParameterizedDefaultQuery = `@query awsAccounts(setupId: String) = foreach cloudAccount in network.cloudAccounts
where cloudAccount.cloudSetupId == setupId
select {
  "Cloud Account Name": cloudAccount.name,
  "Cloud Account ID": cloudAccount.id,
  "Cloud Type": cloudAccount.cloudType,
  "Cloud Setup ID": cloudAccount.cloudSetupId,
  "Organizational Unit IDs": cloudAccount.organizationalUnitIds,
  "Collected?": cloudAccount.collected
};`

const (
	CredentialModeForwardRole     = "forward-role"
	CredentialModeStaticKeys      = "static-keys"
	CredentialModeInstanceProfile = "instance-profile"
	collectorSecretPlaceholder    = "REPLACE_WITH_COLLECTOR_SECRET_ACCESS_KEY"
)

type Config struct {
	Host                       string
	Username                   string
	Password                   string
	NetworkID                  string
	SnapshotID                 string
	Query                      string
	QueryID                    string
	QuerySetupParam            string
	SetupIDs                   []string
	Output                     string
	ManualOutput               string
	APIPrefix                  string
	Insecure                   bool
	Timeout                    time.Duration
	Apply                      bool
	AllowRemovals              bool
	MaxRemovals                int
	MaxRemovalPercent          float64
	AllowNoCandidates          bool
	AllowNoOrgEvidence         bool
	PruneMissing               bool
	MaxSnapshotAge             time.Duration
	ExternalIDFile             string
	Source                     string
	AuthoritativeInput         bool
	Policy                     ReconcilePolicy
	PinSnapshot                bool
	ExpectedPayloadSHA256      string
	ExpectedPlanDigest         string
	AllowMalformedRows         bool
	Unattended                 bool
	AllowUnattendedDestructive bool
	AuthorizationActor         string
}

// ReconcilePolicyFromLegacyFlags is the CLI-boundary compatibility mapping for
// the legacy reconciliation booleans.
func ReconcilePolicyFromLegacyFlags(pruneMissing, authoritativeInput, allowNoOrgEvidence bool, planningInstant time.Time) ReconcilePolicy {
	kind := Additive
	if pruneMissing || authoritativeInput {
		kind = CompleteInventory
	}
	evidence := RequireOrganizationEvidence
	if allowNoOrgEvidence {
		evidence = AllowMissingOrganizationEvidence
	}
	if authoritativeInput {
		evidence = ReviewedAuthoritativeInventory
	}
	return ReconcilePolicy{
		Kind:                 kind,
		PlanningInstant:      planningInstant,
		OrganizationEvidence: evidence,
	}
}

func prepareReconcileConfig(cfg Config, planningInstant time.Time) Config {
	if cfg.Policy.Kind == "" {
		cfg.Policy = ReconcilePolicyFromLegacyFlags(
			cfg.PruneMissing,
			cfg.AuthoritativeInput,
			cfg.AllowNoOrgEvidence,
			planningInstant,
		)
	} else {
		if cfg.Policy.PlanningInstant.IsZero() {
			cfg.Policy.PlanningInstant = planningInstant
		}
		if cfg.Policy.OrganizationEvidence == "" {
			cfg.Policy.OrganizationEvidence = RequireOrganizationEvidence
			if cfg.AuthoritativeInput {
				cfg.Policy.OrganizationEvidence = ReviewedAuthoritativeInventory
			} else if cfg.AllowNoOrgEvidence {
				cfg.Policy.OrganizationEvidence = AllowMissingOrganizationEvidence
			}
		} else if cfg.AllowNoOrgEvidence && cfg.Policy.OrganizationEvidence == RequireOrganizationEvidence {
			cfg.Policy.OrganizationEvidence = AllowMissingOrganizationEvidence
		}
	}
	return cfg
}

type Summary struct {
	Host                string                          `json:"host"`
	NetworkID           string                          `json:"network_id"`
	SnapshotID          string                          `json:"snapshot_id,omitempty"`
	Source              string                          `json:"source,omitempty"`
	AWSOrganizationID   string                          `json:"aws_organization_id,omitempty"`
	AWSManagementID     string                          `json:"aws_management_account_id,omitempty"`
	AWSAccountCount     int                             `json:"aws_account_count,omitempty"`
	AWSSkippedCount     int                             `json:"aws_skipped_account_count,omitempty"`
	CredentialMode      string                          `json:"credential_mode,omitempty"`
	Regions             []string                        `json:"regions,omitempty"`
	CreatePayloadReady  bool                            `json:"create_payload_ready,omitempty"`
	PostedSetupCount    int                             `json:"posted_setup_count,omitempty"`
	CreatePayload       *api.CreateAWSPayload           `json:"create_payload,omitempty"`
	ManualAccountData   []ManualAccountData             `json:"manual_account_data,omitempty"`
	QueryID             string                          `json:"query_id,omitempty"`
	QueryOverride       bool                            `json:"query_override"`
	QuerySetupParam     string                          `json:"query_setup_param,omitempty"`
	SetupIDs            []string                        `json:"setup_ids,omitempty"`
	SelectedSetupIDs    []string                        `json:"selected_setup_ids,omitempty"`
	Output              string                          `json:"output"`
	PayloadSHA256       string                          `json:"payload_sha256,omitempty"`
	ManualOutput        string                          `json:"manual_output,omitempty"`
	ManualPayloadSHA256 string                          `json:"manual_payload_sha256,omitempty"`
	ManualPayloads      map[string][]api.AssumeRoleInfo `json:"manual_payloads,omitempty"`
	RollbackOutput      string                          `json:"rollback_output,omitempty"`
	RollbackSHA256      string                          `json:"rollback_sha256,omitempty"`
	PlanDigest          string                          `json:"plan_digest,omitempty"`
	ResultJournalOutput string                          `json:"result_journal_output,omitempty"`
	ApplyJournal        *ApplyJournal                   `json:"apply_journal,omitempty"`
	Apply               bool                            `json:"apply"`
	FetchedItemCount    int                             `json:"fetched_item_count"`
	IgnoredNQEItemCount int                             `json:"ignored_nqe_item_count,omitempty"`
	IgnoredNQEAccounts  []AccountSummary                `json:"ignored_nqe_accounts,omitempty"`
	SkippedNQERows      []MalformedNQERowSummary        `json:"skipped_nqe_rows,omitempty"`
	PlannedSetupCount   int                             `json:"planned_setup_count"`
	PatchedSetupCount   int                             `json:"patched_setup_count"`
	SkippedSetupCount   int                             `json:"skipped_setup_count"`
	PlannedSetups       []SetupSummary                  `json:"planned_setups"`
	SkippedSetups       []SkipSummary                   `json:"skipped_setups,omitempty"`
	CandidateCheck      []CandidateCheck                `json:"candidate_check,omitempty"`
	RemovalBlocked      bool                            `json:"removal_blocked,omitempty"`
}

type CandidateCheck struct {
	SetupID                string `json:"setup_id"`
	ConfiguredAccountCount int    `json:"configured_account_count"`
	NQEAccountRowCount     int    `json:"nqe_account_row_count"`
	NQECollectedRowCount   int    `json:"nqe_collected_row_count"`
	NQECandidateRowCount   int    `json:"nqe_candidate_row_count"`
	NQEOrgUnitRowCount     int    `json:"nqe_org_unit_row_count"`
	Status                 string `json:"status"`
	Passed                 bool   `json:"passed"`
	Message                string `json:"message,omitempty"`
}

type SetupSummary struct {
	SetupID                      string            `json:"setup_id"`
	RoleName                     string            `json:"role_name"`
	OrgID                        int               `json:"org_id,omitempty"`
	ExternalIDConfigured         bool              `json:"external_id_configured"`
	ExternalIDConsistent         bool              `json:"external_id_consistent"`
	ProxyServerID                string            `json:"proxy_server_id,omitempty"`
	RegionToProxyServerID        map[string]string `json:"region_to_proxy_server_id,omitempty"`
	Regions                      []string          `json:"regions,omitempty"`
	ConfiguredAccountCount       int               `json:"configured_account_count"`
	NQEAccountRowCount           int               `json:"nqe_account_row_count"`
	NQECollectedRowCount         int               `json:"nqe_collected_row_count"`
	NQECandidateRowCount         int               `json:"nqe_candidate_row_count"`
	NQEOrgUnitRowCount           int               `json:"nqe_org_unit_row_count"`
	OrganizationDiscoverySignal  string            `json:"organization_discovery_signal"`
	OrganizationDiscoveryMessage string            `json:"organization_discovery_message"`
	PlannedPayloadAccountCount   int               `json:"planned_payload_account_count"`
	AddedAccounts                []AccountSummary  `json:"added_accounts,omitempty"`
	RemovedAccounts              []AccountSummary  `json:"removed_accounts,omitempty"`
	ReenabledAccounts            []AccountSummary  `json:"reenabled_accounts,omitempty"`
	DisabledAccounts             []AccountSummary  `json:"disabled_accounts,omitempty"`
	UnchangedAccountCount        int               `json:"unchanged_account_count"`
	Patched                      bool              `json:"patched"`
	ApplyStatus                  ApplyStatus       `json:"apply_status"`
	ApplyError                   string            `json:"apply_error,omitempty"`
}

type AccountSummary struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
}

type SkipSummary struct {
	SetupID string `json:"setup_id"`
	Reason  string `json:"reason"`
}

type auditPayloads map[string]api.PatchPayload

type AWSOrganizationAccount struct {
	ID        string
	Name      string
	Email     string
	State     string
	Status    string
	ParentIDs []string
}

type AWSOrganizationSource struct {
	OrganizationID      string
	ManagementAccountID string
	Accounts            []AWSOrganizationAccount
	SkippedAccountCount int
	Partition           string
	Source              string
	DiscoveryMessage    string
}

type ManualAccountData struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	RoleArn    *string `json:"roleArn,omitempty"`
	ExternalID *string `json:"externalId,omitempty"`
	ErrorMsg   *string `json:"errorMsg,omitempty"`
}

type AWSOrganizationConfig struct {
	Host                     string
	Username                 string
	Password                 string
	NetworkID                string
	SetupIDs                 []string
	Output                   string
	ManualOutput             string
	RoleName                 string
	ExternalID               string
	Regions                  []string
	CredentialMode           string
	CollectorAccessKeyID     string
	CollectorSecretAccessKey string
	Post                     bool
	APIPrefix                string
	Insecure                 bool
	Timeout                  time.Duration
	IncludeManual            bool
	Partition                string
}

func Run(ctx context.Context, cfg Config) (*Summary, error) {
	cfg = prepareReconcileConfig(cfg, time.Now().UTC())
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
	if cfg.PinSnapshot && strings.TrimSpace(cfg.SnapshotID) == "" {
		if err := pinLatestProcessedSnapshot(ctx, client, &cfg); err != nil {
			return nil, err
		}
	} else if err := validateSnapshotFreshness(ctx, client, cfg); err != nil {
		return nil, err
	}
	if err := validateQuerySetupParam(cfg); err != nil {
		return nil, err
	}
	query, queryID, parameters := queryInputs(cfg)
	queryResult, err := client.QueryAWSAccountsWithMetadata(ctx, cfg.NetworkID, cfg.SnapshotID, query, queryID, parameters, cfg.SetupIDs)
	if err != nil {
		return nil, err
	}
	cloudAccounts, err := client.CloudAccounts(ctx, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	snapshot, err := parseNQESnapshotFromMapsWithOptions(queryResult.Items, nqeParseOptionsFromQueryResult(queryResult, cfg.AllowMalformedRows))
	if err != nil {
		return nil, err
	}
	snapshot.Source = "nqe"
	snapshot.NetworkID = cfg.NetworkID
	snapshot.SnapshotID = cfg.SnapshotID
	return runPlannedSyncFromSnapshot(ctx, cfg, client, snapshot, cloudAccounts)
}

func runPlannedSync(
	ctx context.Context,
	cfg Config,
	client *api.Client,
	items []map[string]any,
	cloudAccounts []api.CloudAccount,
) (*Summary, error) {
	cfg = prepareReconcileConfig(cfg, time.Now().UTC())
	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		AllowMalformedRows: cfg.AllowMalformedRows,
		Completeness:       InventoryCompletenessComplete,
	})
	if err != nil {
		return nil, err
	}
	snapshot.Source = "nqe"
	snapshot.NetworkID = cfg.NetworkID
	snapshot.SnapshotID = cfg.SnapshotID
	return runPlannedSyncFromSnapshot(ctx, cfg, client, snapshot, cloudAccounts)
}

func runPlannedSyncFromSnapshot(
	ctx context.Context,
	cfg Config,
	client *api.Client,
	snapshot *InventorySnapshot,
	cloudAccounts []api.CloudAccount,
) (*Summary, error) {
	planOptions, err := buildPlanOptionsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	plan, err := buildPlanFromSnapshot(snapshot, cloudAccounts, cfg.SetupIDs, planOptions)
	if err != nil {
		return nil, err
	}
	outputPath := strings.TrimSpace(cfg.Output)
	if outputPath == "" {
		outputPath = defaultOutputPath()
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	payloadSHA256, err := writeAuditPayloads(outputPath, plan.Payloads)
	if err != nil {
		return nil, err
	}
	if expected := strings.TrimSpace(cfg.ExpectedPayloadSHA256); expected != "" &&
		!strings.EqualFold(expected, payloadSHA256) {
		return nil, fmt.Errorf(
			"reviewed plan changed before apply: expected payload SHA-256 %s, got %s; no PATCH was sent",
			expected,
			payloadSHA256,
		)
	}
	manualPayloads := buildManualPayloads(plan.Payloads)
	manualOutputPath := ""
	manualPayloadSHA256 := ""
	var manualPayloadsForSummary map[string][]api.AssumeRoleInfo
	if strings.TrimSpace(cfg.ManualOutput) != "" {
		manualOutputPath, manualPayloadSHA256, err = writeManualPayloads(cfg.ManualOutput, manualPayloads)
		if err != nil {
			return nil, err
		}
		manualPayloadsForSummary = manualPayloads
	}
	intent, err := newApplyIntent(cfg, snapshot, cloudAccounts, plan, outputPath)
	if err != nil {
		return nil, err
	}

	summary := buildSummary(
		cfg,
		outputPath,
		payloadSHA256,
		manualOutputPath,
		manualPayloadSHA256,
		manualPayloadsForSummary,
		snapshot.ObservedRowCount,
		plan,
		0,
	)
	summary.PlanDigest = intent.Digest()
	if !cfg.Apply {
		return summary, nil
	}
	approvedDigest := intent.Digest()
	if strings.TrimSpace(cfg.ExpectedPlanDigest) != "" {
		approvedDigest = strings.TrimSpace(cfg.ExpectedPlanDigest)
	}
	actor := strings.TrimSpace(cfg.AuthorizationActor)
	if actor == "" {
		if cfg.Unattended {
			actor = "unattended app caller"
		} else {
			actor = "attended app caller"
		}
	}
	applyResult, applyErr := GuardAndApply(ctx, client, intent, ApplyAuthorization{
		PlanDigest:                 approvedDigest,
		Actor:                      actor,
		Approved:                   true,
		AllowDestructive:           cfg.AllowRemovals,
		MaxRemovals:                cfg.MaxRemovals,
		MaxRemovalPercent:          cfg.MaxRemovalPercent,
		AllowNoCandidates:          cfg.AllowNoCandidates,
		Unattended:                 cfg.Unattended,
		AllowUnattendedDestructive: cfg.AllowUnattendedDestructive,
	})
	applyResultToSummary(summary, applyResult)
	if applyErr != nil && applyResult.JournalOutput != "" {
		return summary, fmt.Errorf("%w; apply result journal: %s", applyErr, applyResult.JournalOutput)
	}
	return summary, applyErr
}

func RunAWSOrganizations(ctx context.Context, cfg AWSOrganizationConfig, source AWSOrganizationSource) (*Summary, error) {
	setupIDs := cleanSetupIDs(cfg.SetupIDs)
	if len(setupIDs) != 1 {
		return nil, fmt.Errorf("discover-org requires exactly one --setup-id; use the NQE sync path to update existing setup IDs")
	}
	setupID := setupIDs[0]
	roleName := strings.TrimSpace(cfg.RoleName)
	if roleName == "" {
		return nil, fmt.Errorf("--role-name is required")
	}
	regions := cleanStrings(cfg.Regions)
	if len(regions) == 0 {
		return nil, fmt.Errorf("at least one --collect-region is required for the Forward create payload")
	}
	credentialMode, err := normalizeCredentialMode(cfg.CredentialMode)
	if err != nil {
		return nil, err
	}
	sourceName := strings.TrimSpace(source.Source)
	if sourceName == "" {
		sourceName = "aws_organizations"
	}
	discoveryMessage := strings.TrimSpace(source.DiscoveryMessage)
	if discoveryMessage == "" {
		discoveryMessage = "AWS Organizations DescribeOrganization, ListAccounts, and ListParents succeeded; account data came directly from AWS Organizations"
	}
	partitionValue := strings.TrimSpace(source.Partition)
	if partitionValue == "" {
		partitionValue = cfg.Partition
	}
	partition, err := normalizeAWSPartition(partitionValue)
	if err != nil {
		return nil, err
	}
	if err := validateRegionsForPartition(regions, partition); err != nil {
		return nil, err
	}
	accounts := awsOrganizationAccountRows(source.Accounts)
	if len(accounts) == 0 {
		return nil, fmt.Errorf("%s returned no accounts", sourceName)
	}

	networkID := strings.TrimSpace(cfg.NetworkID)
	externalID := strings.TrimSpace(cfg.ExternalID)
	var client *api.Client
	if strings.TrimSpace(cfg.Host) != "" {
		client, err = api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		networkID, err = ResolveNetworkID(ctx, client, networkID)
		if err != nil {
			return nil, err
		}
		cloudAccounts, err := client.CloudAccounts(ctx, networkID)
		if err != nil {
			return nil, err
		}
		if cloudAccountNameExists(cloudAccounts, setupID) {
			return nil, fmt.Errorf("Forward cloud account setup %q already exists; use awssync NQE sync to update existing setups", setupID)
		}
		if externalID == "" {
			externalID, err = client.AWSAssumeRoleExternalID(ctx, networkID)
			if err != nil {
				return nil, fmt.Errorf("get Forward AWS external ID: %w", err)
			}
			if externalID == "" {
				return nil, fmt.Errorf("Forward did not return an AWS external ID; pass --external-id")
			}
		}
	}

	manualAccountData := buildManualAccountData(accounts, roleName, externalID, partition)
	createPayload, createPayloadReady, err := buildCreateAWSPayload(setupID, accounts, roleName, externalID, regions, credentialMode, partition, cfg)
	if err != nil {
		return nil, err
	}

	outputPath := strings.TrimSpace(cfg.Output)
	if outputPath == "" {
		outputPath = defaultCreateOutputPath()
	}
	outputPath, payloadSHA256, err := writeJSONPayload(outputPath, createPayload)
	if err != nil {
		return nil, err
	}

	manualOutput := strings.TrimSpace(cfg.ManualOutput)
	if manualOutput == "" && cfg.IncludeManual {
		manualOutput = defaultManualOutputPath()
	}
	manualOutputPath := ""
	manualPayloadSHA256 := ""
	if manualOutput != "" {
		manualOutputPath, manualPayloadSHA256, err = writeManualAccountData(manualOutput, manualAccountData)
		if err != nil {
			return nil, err
		}
	}

	postedCount := 0
	if cfg.Post {
		if client == nil {
			return nil, fmt.Errorf("--post requires Forward --host, --username, --password, and --network-id")
		}
		if !createPayloadReady {
			return nil, fmt.Errorf("--post requires a complete create payload; provide --collector-secret-access-key or AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY for static-keys mode")
		}
		if err := client.CreateCloudAccount(ctx, networkID, createPayload); err != nil {
			return nil, fmt.Errorf("create Forward AWS setup %s: %w", setupID, err)
		}
		postedCount = 1
	}

	regionList := append([]string(nil), regions...)
	sort.Strings(regionList)
	accountSummaries := accountSummaries(accounts)
	redactedPayload := redactCreatePayload(createPayload)
	summary := &Summary{
		Host:                cfg.Host,
		NetworkID:           networkID,
		Source:              sourceName,
		AWSOrganizationID:   source.OrganizationID,
		AWSManagementID:     source.ManagementAccountID,
		AWSAccountCount:     len(source.Accounts),
		AWSSkippedCount:     source.SkippedAccountCount,
		CredentialMode:      credentialMode,
		Regions:             regionList,
		CreatePayloadReady:  createPayloadReady,
		PostedSetupCount:    postedCount,
		CreatePayload:       &redactedPayload,
		ManualAccountData:   manualAccountData,
		SetupIDs:            setupIDs,
		SelectedSetupIDs:    setupIDs,
		Output:              outputPath,
		PayloadSHA256:       payloadSHA256,
		ManualOutput:        manualOutputPath,
		ManualPayloadSHA256: manualPayloadSHA256,
		Apply:               false,
		FetchedItemCount:    len(accounts),
		PlannedSetupCount:   1,
		PatchedSetupCount:   0,
		PlannedSetups: []SetupSummary{{
			SetupID:                      setupID,
			RoleName:                     roleName,
			ExternalIDConfigured:         externalID != "",
			ExternalIDConsistent:         true,
			Regions:                      regionList,
			ConfiguredAccountCount:       0,
			NQEAccountRowCount:           0,
			NQECollectedRowCount:         0,
			NQECandidateRowCount:         0,
			NQEOrgUnitRowCount:           countAccountsWithOrgUnit(source.Accounts),
			OrganizationDiscoverySignal:  sourceName,
			OrganizationDiscoveryMessage: discoveryMessage,
			PlannedPayloadAccountCount:   len(createPayload.AssumeRoleInfos),
			AddedAccounts:                accountSummaries,
			UnchangedAccountCount:        0,
			Patched:                      false,
		}},
	}
	summary.Source = sourceName
	summary.AWSOrganizationID = source.OrganizationID
	summary.AWSManagementID = source.ManagementAccountID
	summary.AWSAccountCount = len(source.Accounts)
	summary.AWSSkippedCount = source.SkippedAccountCount
	return summary, nil
}

func normalizeCredentialMode(mode string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return CredentialModeForwardRole, nil
	}
	switch mode {
	case CredentialModeForwardRole, CredentialModeStaticKeys, CredentialModeInstanceProfile:
		return mode, nil
	default:
		return "", fmt.Errorf(
			"invalid credential mode %q; expected %q, %q, or %q",
			mode,
			CredentialModeForwardRole,
			CredentialModeStaticKeys,
			CredentialModeInstanceProfile,
		)
	}
}

func normalizeAWSPartition(partition string) (string, error) {
	partition = strings.TrimSpace(strings.ToLower(partition))
	if partition == "" {
		return "aws", nil
	}
	switch partition {
	case "aws", "aws-us-gov", "aws-cn":
		return partition, nil
	default:
		return "", fmt.Errorf("invalid AWS partition %q; expected aws, aws-us-gov, or aws-cn", partition)
	}
}

func validateRegionsForPartition(regions []string, partition string) error {
	for _, region := range regions {
		region = strings.TrimSpace(strings.ToLower(region))
		if region == "" {
			continue
		}
		valid := false
		switch partition {
		case "aws-us-gov":
			valid = strings.HasPrefix(region, "us-gov-")
		case "aws-cn":
			valid = strings.HasPrefix(region, "cn-")
		case "aws":
			valid = !strings.HasPrefix(region, "us-gov-") && !strings.HasPrefix(region, "cn-")
		}
		if !valid {
			return fmt.Errorf("AWS region %q does not belong to partition %q", region, partition)
		}
	}
	return nil
}

func cloudAccountNameExists(cloudAccounts []api.CloudAccount, setupID string) bool {
	setupID = strings.TrimSpace(setupID)
	for _, account := range cloudAccounts {
		if strings.TrimSpace(account.Name) == setupID {
			return true
		}
	}
	return false
}

func awsOrganizationAccountRows(accounts []AWSOrganizationAccount) []accountRow {
	rows := make([]accountRow, 0, len(accounts))
	for _, account := range accounts {
		accountID := strings.TrimSpace(account.ID)
		if accountID == "" {
			continue
		}
		accountName := strings.TrimSpace(account.Name)
		if accountName == "" {
			accountName = accountID
		}
		rows = append(rows, accountRow{AccountID: accountID, AccountName: accountName})
	}
	rows = dedupeAccounts(rows)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].AccountID < rows[j].AccountID
	})
	return rows
}

func buildManualAccountData(accounts []accountRow, roleName, externalID, partition string) []ManualAccountData {
	result := make([]ManualAccountData, 0, len(accounts))
	for _, account := range accounts {
		roleArn := roleARN(partition, account.AccountID, roleName)
		entry := ManualAccountData{
			ID:      account.AccountID,
			Name:    account.AccountName,
			RoleArn: &roleArn,
		}
		if externalID != "" {
			entry.ExternalID = &externalID
		}
		result = append(result, entry)
	}
	return result
}

func buildCreateAWSPayload(
	setupID string,
	accounts []accountRow,
	roleName string,
	externalID string,
	regions []string,
	credentialMode string,
	partition string,
	cfg AWSOrganizationConfig,
) (api.CreateAWSPayload, bool, error) {
	payload := api.CreateAWSPayload{
		Type:            "AWS",
		Name:            setupID,
		Collect:         true,
		Regions:         selectedRegionMap(regions),
		AssumeRoleInfos: buildAssumeRoleInfosForPartition(accounts, roleName, externalID, partition),
	}
	ready := true
	switch credentialMode {
	case CredentialModeForwardRole:
		useForwardAccount := true
		payload.UseForwardAccountToAssumeRole = &useForwardAccount
	case CredentialModeStaticKeys:
		useForwardAccount := false
		payload.UseForwardAccountToAssumeRole = &useForwardAccount
		payload.Username = strings.TrimSpace(cfg.CollectorAccessKeyID)
		if payload.Username == "" {
			return payload, false, fmt.Errorf("--collector-access-key-id is required with --credential-mode static-keys")
		}
		payload.Password = cfg.CollectorSecretAccessKey
		if strings.TrimSpace(payload.Password) == "" {
			payload.Password = collectorSecretPlaceholder
			ready = false
		}
	case CredentialModeInstanceProfile:
		useForwardAccount := false
		payload.UseForwardAccountToAssumeRole = &useForwardAccount
	default:
		return payload, false, fmt.Errorf("invalid credential mode %q", credentialMode)
	}
	return payload, ready, nil
}

func selectedRegionMap(regions []string) map[string]int64 {
	result := make(map[string]int64, len(regions))
	currentEpochMs := time.Now().UnixMilli()
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		result[region] = currentEpochMs
	}
	return result
}

func countAccountsWithOrgUnit(accounts []AWSOrganizationAccount) int {
	count := 0
	for _, account := range accounts {
		for _, parentID := range account.ParentIDs {
			if strings.HasPrefix(strings.TrimSpace(parentID), "ou-") {
				count++
				break
			}
		}
	}
	return count
}

func redactCreatePayload(payload api.CreateAWSPayload) api.CreateAWSPayload {
	if payload.Password != "" {
		payload.Password = "<redacted>"
	}
	return payload
}

func cleanStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			result = append(result, part)
		}
	}
	sort.Strings(result)
	return result
}

func defaultOutputPath() string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	return "aws_sync_payload_" + timestamp + ".json"
}

func defaultCreateOutputPath() string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	return "aws_create_payload_" + timestamp + ".json"
}

func defaultManualOutputPath() string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	return "fwd_accounts_data_" + timestamp + ".json"
}

func validateSnapshotFreshness(ctx context.Context, client *api.Client, cfg Config) error {
	if cfg.MaxSnapshotAge <= 0 || strings.TrimSpace(cfg.SnapshotID) != "" {
		return nil
	}
	latest, err := client.LatestProcessedSnapshot(ctx, cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("check latest processed snapshot freshness: %w", err)
	}
	snapshotTime, err := snapshotTimestamp(*latest)
	if err != nil {
		return fmt.Errorf("check latest processed snapshot freshness: %w", err)
	}
	age := time.Since(snapshotTime)
	if age > cfg.MaxSnapshotAge {
		return fmt.Errorf(
			"latest processed snapshot %s is stale: age %s exceeds max %s; pass --snapshot-id or increase --max-snapshot-age",
			latest.ID,
			age.Round(time.Second),
			cfg.MaxSnapshotAge,
		)
	}
	return nil
}

func pinLatestProcessedSnapshot(ctx context.Context, client *api.Client, cfg *Config) error {
	latest, err := client.LatestProcessedSnapshot(ctx, cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("pin latest processed snapshot: %w", err)
	}
	if cfg.MaxSnapshotAge > 0 {
		snapshotTime, err := snapshotTimestamp(*latest)
		if err != nil {
			return fmt.Errorf("check latest processed snapshot freshness: %w", err)
		}
		age := time.Since(snapshotTime)
		if age > cfg.MaxSnapshotAge {
			return fmt.Errorf(
				"latest processed snapshot %s is stale: age %s exceeds max %s; pass --snapshot-id or increase --max-snapshot-age",
				latest.ID,
				age.Round(time.Second),
				cfg.MaxSnapshotAge,
			)
		}
	}
	cfg.SnapshotID = latest.ID
	return nil
}

func snapshotTimestamp(snapshot api.SnapshotInfo) (time.Time, error) {
	for _, value := range []string{snapshot.ProcessedAt, snapshot.CreatedAt} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse snapshot timestamp %q: %w", value, err)
		}
		return parsed, nil
	}
	return time.Time{}, fmt.Errorf("latest processed snapshot did not include processedAt or createdAt")
}

func validateQuerySetupParam(cfg Config) error {
	if strings.TrimSpace(cfg.QuerySetupParam) == "" {
		return nil
	}
	if strings.TrimSpace(cfg.QueryID) == "" {
		return fmt.Errorf("--query-setup-param is only valid with --query-id")
	}
	setupIDs := cleanSetupIDs(cfg.SetupIDs)
	if len(setupIDs) != 1 {
		return fmt.Errorf("--query-setup-param requires exactly one --setup-id")
	}
	return nil
}

func queryInputs(cfg Config) (string, string, map[string]any) {
	queryID := strings.TrimSpace(cfg.QueryID)
	if queryID != "" {
		querySetupParam := strings.TrimSpace(cfg.QuerySetupParam)
		if querySetupParam != "" {
			return "", queryID, map[string]any{querySetupParam: cleanSetupIDs(cfg.SetupIDs)[0]}
		}
		return "", queryID, nil
	}
	query := strings.TrimSpace(cfg.Query)
	if query == "" {
		setupIDs := cleanSetupIDs(cfg.SetupIDs)
		if len(setupIDs) == 1 {
			return ParameterizedDefaultQuery, "", map[string]any{"setupId": setupIDs[0]}
		}
		query = DefaultQuery
	}
	return query, "", nil
}

func buildSummary(
	cfg Config,
	outputPath string,
	payloadSHA256 string,
	manualOutputPath string,
	manualPayloadSHA256 string,
	manualPayloads map[string][]api.AssumeRoleInfo,
	fetchedItemCount int,
	plan *patchPlan,
	patchedCount int,
) *Summary {
	setupSummaries := make([]SetupSummary, 0, len(plan.Setups))
	for _, setup := range plan.Setups {
		regions := make([]string, 0, len(setup.Payload.Regions))
		for region := range setup.Payload.Regions {
			regions = append(regions, region)
		}
		sort.Strings(regions)
		discoverySignal := organizationDiscoveryStatus(setup.DiscoveredCandidateCount, setup.DiscoveredOrgUnitRowCount)
		discoveryMessage := organizationDiscoveryMessage(setup.DiscoveredCandidateCount, setup.DiscoveredOrgUnitRowCount)
		if cfg.Policy.OrganizationEvidence == ReviewedAuthoritativeInventory {
			discoverySignal = "account_manifest"
			discoveryMessage = "Account inventory came from the explicitly reviewed manifest; AWS Organizations was not queried"
		} else if cfg.Policy.Kind == Additive {
			discoveryMessage += "; additive mode preserves currently configured accounts that are absent from NQE"
		}
		setupSummaries = append(setupSummaries, SetupSummary{
			SetupID:                      setup.SetupID,
			RoleName:                     setup.RoleName,
			OrgID:                        setup.OrgID,
			ExternalIDConfigured:         setup.ExternalIDConfigured,
			ExternalIDConsistent:         setup.ExternalIDConsistent,
			ProxyServerID:                setup.ProxyServerID,
			RegionToProxyServerID:        nonEmptyStringMap(setup.Payload.RegionToProxyServerID),
			Regions:                      regions,
			ConfiguredAccountCount:       len(setup.CurrentAccounts),
			NQEAccountRowCount:           len(setup.DiscoveredAccounts),
			NQECollectedRowCount:         setup.DiscoveredCollectedCount,
			NQECandidateRowCount:         setup.DiscoveredCandidateCount,
			NQEOrgUnitRowCount:           setup.DiscoveredOrgUnitRowCount,
			OrganizationDiscoverySignal:  discoverySignal,
			OrganizationDiscoveryMessage: discoveryMessage,
			PlannedPayloadAccountCount:   len(setup.Payload.AssumeRoleInfos),
			AddedAccounts:                accountSummaries(setup.AddedAccounts),
			RemovedAccounts:              accountSummaries(setup.RemovedAccounts),
			ReenabledAccounts:            accountSummaries(setup.ReenabledAccounts),
			DisabledAccounts:             accountSummaries(setup.DisabledAccounts),
			UnchangedAccountCount:        len(setup.UnchangedAccounts),
			ApplyStatus:                  ApplyStatusPlanned,
		})
	}

	return &Summary{
		Host:                cfg.Host,
		NetworkID:           cfg.NetworkID,
		Source:              strings.TrimSpace(cfg.Source),
		SnapshotID:          cfg.SnapshotID,
		QueryID:             strings.TrimSpace(cfg.QueryID),
		QueryOverride:       strings.TrimSpace(cfg.QueryID) != "",
		QuerySetupParam:     strings.TrimSpace(cfg.QuerySetupParam),
		SetupIDs:            cleanSetupIDs(cfg.SetupIDs),
		SelectedSetupIDs:    selectedSetupIDs(plan.Setups),
		Output:              outputPath,
		PayloadSHA256:       payloadSHA256,
		ManualOutput:        manualOutputPath,
		ManualPayloadSHA256: manualPayloadSHA256,
		ManualPayloads:      manualPayloads,
		Apply:               cfg.Apply,
		FetchedItemCount:    fetchedItemCount,
		IgnoredNQEItemCount: len(plan.IgnoredAccounts),
		IgnoredNQEAccounts:  plan.IgnoredAccounts,
		SkippedNQERows:      plan.SkippedRows,
		PlannedSetupCount:   len(plan.Setups),
		PatchedSetupCount:   patchedCount,
		SkippedSetupCount:   len(plan.Skips),
		PlannedSetups:       setupSummaries,
		SkippedSetups:       plan.Skips,
		CandidateCheck:      plan.CandidateChecks,
	}
}

func applyResultToSummary(summary *Summary, result ApplyResult) {
	summary.PatchedSetupCount = result.PatchedCount
	summary.RollbackOutput = result.RollbackOutput
	summary.RollbackSHA256 = result.RollbackSHA256
	summary.ResultJournalOutput = result.JournalOutput
	summary.RemovalBlocked = result.Blocked
	journal := result.Journal
	summary.ApplyJournal = &journal
	entries := make(map[string]ApplyJournalEntry, len(result.Journal.Setups))
	for _, entry := range result.Journal.Setups {
		entries[entry.SetupID] = entry
	}
	for index := range summary.PlannedSetups {
		entry, ok := entries[summary.PlannedSetups[index].SetupID]
		if !ok {
			continue
		}
		summary.PlannedSetups[index].ApplyStatus = entry.Status
		summary.PlannedSetups[index].ApplyError = entry.Error
		summary.PlannedSetups[index].Patched = entry.Status == ApplyStatusApplied
	}
}

func selectedSetupIDs(setups []plannedSetup) []string {
	result := make([]string, 0, len(setups))
	for _, setup := range setups {
		if strings.TrimSpace(setup.SetupID) != "" {
			result = append(result, setup.SetupID)
		}
	}
	sort.Strings(result)
	return result
}

type patchPlan struct {
	Payloads        auditPayloads
	Setups          []plannedSetup
	Skips           []SkipSummary
	CandidateChecks []CandidateCheck
	IgnoredAccounts []AccountSummary
	SkippedRows     []MalformedNQERowSummary
}

type plannedSetup struct {
	SetupID                   string
	RoleName                  string
	OrgID                     int
	ExternalIDConfigured      bool
	ExternalIDConsistent      bool
	ProxyServerID             string
	Payload                   api.PatchPayload
	ChangeSet                 ChangeSet
	AddedAccounts             []accountRow
	RemovedAccounts           []accountRow
	ReenabledAccounts         []accountRow
	DisabledAccounts          []accountRow
	UnchangedAccounts         []accountRow
	CurrentAccounts           []accountRow
	DiscoveredAccounts        []accountRow
	DiscoveredCollectedCount  int
	DiscoveredCandidateCount  int
	DiscoveredOrgUnitRowCount int
}

func (p *patchPlan) HasCandidateRisk() bool {
	for _, setup := range p.Setups {
		if setup.DiscoveredCandidateCount == 0 {
			return true
		}
	}
	return false
}

func (p *patchPlan) HasCandidateRemovalRisk() bool {
	for _, setup := range p.Setups {
		if setup.DiscoveredCandidateCount == 0 && len(setup.RemovedAccounts) > 0 {
			return true
		}
	}
	return false
}

func (p *patchPlan) HasNoOrganizationEvidenceForRemovals() bool {
	for _, setup := range p.Setups {
		if len(setup.RemovedAccounts) == 0 {
			continue
		}
		if organizationDiscoveryVisible(setup.DiscoveredCandidateCount, setup.DiscoveredOrgUnitRowCount) {
			continue
		}
		return true
	}
	return false
}

func (p *patchPlan) setupsWithoutOrganizationEvidenceForRemovals() []string {
	missing := make([]string, 0)
	for _, setup := range p.Setups {
		if len(setup.RemovedAccounts) == 0 {
			continue
		}
		if organizationDiscoveryVisible(setup.DiscoveredCandidateCount, setup.DiscoveredOrgUnitRowCount) {
			continue
		}
		missing = append(missing, setup.SetupID)
	}
	sort.Strings(missing)
	return missing
}

func (p *patchPlan) HasRemovals() bool {
	for _, setup := range p.Setups {
		if len(setup.RemovedAccounts) > 0 {
			return true
		}
	}
	return false
}

func (p *patchPlan) HasGovCloudRemovalsWithoutOrganizationEvidence() bool {
	for _, setup := range p.Setups {
		if len(setup.RemovedAccounts) == 0 || organizationDiscoveryVisible(
			setup.DiscoveredCandidateCount,
			setup.DiscoveredOrgUnitRowCount,
		) {
			continue
		}
		if extractRolePartition(setup.Payload.AssumeRoleInfos) == "aws-us-gov" {
			return true
		}
	}
	return false
}

type buildPlanOptions struct {
	RoleNameBySetup     map[string]string
	ExternalIDBySetup   map[string]string
	ExternalIDByAccount externalIDAssignments
	Policy              ReconcilePolicy
	PreserveMissing     bool
}

// buildPlan is a test-only helper. It asserts a proven-complete inventory so
// fixtures can exercise removal paths directly; production callers must derive
// completeness from real pagination metadata via buildPlanForConfig.
func buildPlan(items []map[string]any, cloudAccounts []api.CloudAccount, queryID string, requestedSetupIDs []string) (*patchPlan, error) {
	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		Completeness: InventoryCompletenessComplete,
	})
	if err != nil {
		return nil, err
	}
	_ = queryID
	return buildPlanFromSnapshot(snapshot, cloudAccounts, requestedSetupIDs, buildPlanOptions{
		Policy: ReconcilePolicy{
			Kind:            CompleteInventory,
			PlanningInstant: time.Unix(1, 0).UTC(),
		},
	})
}

func buildPlanForConfig(cfg Config, items []map[string]any, cloudAccounts []api.CloudAccount) (*patchPlan, error) {
	cfg = prepareReconcileConfig(cfg, time.Unix(1, 0).UTC())
	planOptions, err := buildPlanOptionsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		AllowMalformedRows: cfg.AllowMalformedRows,
		Completeness:       InventoryCompletenessComplete,
	})
	if err != nil {
		return nil, err
	}
	return buildPlanFromSnapshot(snapshot, cloudAccounts, cfg.SetupIDs, planOptions)
}

func buildPlanOptionsFromConfig(cfg Config) (buildPlanOptions, error) {
	defaultSetupID := ""
	setupIDs := cleanSetupIDs(cfg.SetupIDs)
	if len(setupIDs) == 1 {
		defaultSetupID = setupIDs[0]
	}
	assignments, err := loadExternalIDAssignments(cfg.ExternalIDFile, defaultSetupID)
	if err != nil {
		return buildPlanOptions{}, err
	}
	adaptedAssignments, err := adaptExternalIDAssignments(assignments)
	if err != nil {
		return buildPlanOptions{}, err
	}
	return buildPlanOptions{
		ExternalIDByAccount: legacyExternalIDAssignments(adaptedAssignments),
		Policy:              cfg.Policy,
	}, nil
}

// buildPlanWithOptions is a test-only helper. See buildPlan on the asserted
// completeness.
func buildPlanWithOptions(items []map[string]any, cloudAccounts []api.CloudAccount, _ string, requestedSetupIDs []string, opts buildPlanOptions) (*patchPlan, error) {
	snapshot, err := parseNQESnapshotFromMapsWithOptions(items, parseNQESnapshotOptions{
		Completeness: InventoryCompletenessComplete,
	})
	if err != nil {
		return nil, err
	}
	convertedAssignments, err := adaptExternalIDAssignments(opts.ExternalIDByAccount)
	if err != nil {
		return nil, err
	}
	kind := CompleteInventory
	if opts.PreserveMissing {
		kind = Additive
	}
	return buildPlanFromSnapshot(snapshot, cloudAccounts, requestedSetupIDs, buildPlanOptions{
		RoleNameBySetup:     opts.RoleNameBySetup,
		ExternalIDBySetup:   opts.ExternalIDBySetup,
		ExternalIDByAccount: legacyExternalIDAssignments(convertedAssignments),
		Policy: ReconcilePolicy{
			Kind:            kind,
			PlanningInstant: time.Unix(1, 0).UTC(),
		},
	})
}

func nqeParseOptionsFromQueryResult(result api.QueryAWSAccountsResult, allowMalformedRows bool) parseNQESnapshotOptions {
	completeness := InventoryCompletenessComplete
	if result.CompletenessUnproven {
		completeness = InventoryCompletenessLikelyIncomplete
	}
	return parseNQESnapshotOptions{
		AllowMalformedRows: allowMalformedRows,
		Completeness:       completeness,
		CompletenessReason: result.CompletenessReason,
		PageLimit:          result.PageLimit,
	}
}

func buildPlanFromSnapshot(snapshot *InventorySnapshot, cloudAccounts []api.CloudAccount, requestedSetupIDs []string, opts buildPlanOptions) (*patchPlan, error) {
	policy := opts.Policy
	if policy.Kind == "" {
		kind := CompleteInventory
		if opts.PreserveMissing {
			kind = Additive
		}
		policy = ReconcilePolicy{Kind: kind, PlanningInstant: time.Unix(1, 0).UTC()}
	}
	if policy.PlanningInstant.IsZero() {
		return nil, fmt.Errorf("reconcile policy planning instant is required")
	}
	cloudMetaMap, err := adaptCloudAccountsBySetupID(cloudAccounts, requestedSetupIDs)
	if err != nil {
		return nil, err
	}
	if len(cloudMetaMap) == 0 {
		return nil, fmt.Errorf("no cloud account metadata available in Forward")
	}

	groupedAccounts := make(map[SetupID][]accountRow)
	groupedDiscovered := make(map[SetupID][]DiscoveredAccount)
	for _, account := range snapshot.DiscoveredAccounts {
		if account.SetupID.IsZero() {
			continue
		}
		groupedDiscovered[account.SetupID] = append(groupedDiscovered[account.SetupID], account)
		groupedAccounts[account.SetupID] = append(groupedAccounts[account.SetupID], accountRow{
			AccountID:   account.AccountID.String(),
			AccountName: account.AccountName,
		})
	}
	if len(groupedAccounts) == 0 && len(snapshot.DiscoveredAccounts) > 0 {
		if setupID, ok := firstSetupID(cloudMetaMap); ok {
			for _, account := range snapshot.DiscoveredAccounts {
				account.SetupID = setupID
				groupedDiscovered[setupID] = append(groupedDiscovered[setupID], account)
			}
			groupedAccounts[setupID] = toAccountRows(groupedDiscovered[setupID])
		}
	}

	for setupIDStr := range opts.ExternalIDByAccount {
		setupID, err := NewSetupID(setupIDStr)
		if err != nil {
			return nil, fmt.Errorf("external ID file contains setup %s: %w", setupIDStr, err)
		}
		if _, ok := groupedAccounts[setupID]; !ok {
			return nil, fmt.Errorf("external ID file contains setup %s, but that setup is not present in the discovered account inventory", setupID)
		}
	}

	if len(groupedAccounts) == 0 {
		if len(cloudMetaMap) > 1 && len(snapshot.DiscoveredAccounts) > 0 {
			return nil, fmt.Errorf("NQE response has AWS accounts but no setup ID data; pass --query-id only if overriding the platform query")
		}
		return nil, fmt.Errorf("no AWS accounts found in query response")
	}
	if err := assertSafeSelectedSetupOwnership(cloudMetaMap, groupedDiscovered); err != nil {
		return nil, err
	}

	plannedSetupIDs := make([]SetupID, 0, len(groupedAccounts))
	for setupID := range groupedAccounts {
		plannedSetupIDs = append(plannedSetupIDs, setupID)
	}
	sort.Slice(plannedSetupIDs, func(i, j int) bool {
		return plannedSetupIDs[i] < plannedSetupIDs[j]
	})

	plan := &patchPlan{
		Payloads:        make(auditPayloads),
		IgnoredAccounts: append([]AccountSummary(nil), snapshot.IgnoredAccounts...),
		SkippedRows:     append([]MalformedNQERowSummary(nil), snapshot.SkippedRows...),
	}
	for _, setupID := range plannedSetupIDs {
		meta, ok := cloudMetaMap[setupID]
		if !ok {
			plan.Skips = append(plan.Skips, SkipSummary{SetupID: setupID.String(), Reason: "setup metadata not found in Forward"})
			continue
		}
		if err := validateCloudAccountPartitionFromMetadata(meta); err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		roleName := extractRoleName(meta.assumeRoleInfos)
		if override := strings.TrimSpace(opts.RoleNameBySetup[setupID.String()]); override != "" {
			roleName = override
		}
		if roleName == "" {
			plan.Skips = append(plan.Skips, SkipSummary{SetupID: setupID.String(), Reason: "unable to determine role ARN name from assumeRoleInfos"})
			continue
		}
		discoveredRows := groupedAccounts[setupID]
		discoveredSet := groupedDiscovered[setupID]
		current := currentAccounts(meta.assumeRoleInfos)
		uniformExternalID, hasUniformOverride := opts.ExternalIDBySetup[setupID.String()]
		setupIDStr := setupID.String()
		if hasUniformOverride && len(opts.ExternalIDByAccount[setupIDStr]) > 0 {
			return nil, fmt.Errorf("setup %s has both setup-wide and per-account External ID overrides", setupID)
		}
		currentSetup, err := adaptCurrentSetup(meta)
		if err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		setupPolicy := policy
		setupPolicy.DefaultRoleName = roleName
		setupPolicy.UniformExternalID = nil
		if hasUniformOverride {
			value := strings.TrimSpace(uniformExternalID)
			setupPolicy.UniformExternalID = &value
		}
		setupPolicy.ExternalIDByAccount = make(map[AccountID]string, len(opts.ExternalIDByAccount[setupIDStr]))
		for rawAccountID, externalID := range opts.ExternalIDByAccount[setupIDStr] {
			accountID, err := NewAccountID(rawAccountID)
			if err != nil {
				return nil, err
			}
			setupPolicy.ExternalIDByAccount[accountID] = externalID
		}
		setupSnapshot := *snapshot
		if setupSnapshot.PageLimit == 0 {
			setupSnapshot.PageLimit = api.PageLimit
		}
		setupSnapshot.DiscoveredAccounts = append([]DiscoveredAccount(nil), discoveredSet...)
		desired, changes, err := ComputeDesired(currentSetup, setupSnapshot, setupPolicy)
		if err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		payload := patchPayloadFromDesired(desired)
		infos := payload.AssumeRoleInfos
		nextAccounts := currentAccounts(infos)
		added, removed, unchanged := accountDiff(current, nextAccounts)
		reenabled := accountRowsFromChanges(changes.Enable, false)
		disabled := accountRowsFromChanges(changes.Disable, false)
		externalIDConfigured, externalIDConsistent := externalIDState(infos)
		externalID := ""
		if externalIDConsistent && len(infos) > 0 {
			externalID = strings.TrimSpace(infos[0].ExternalID)
		}
		orgID := parseOrgID(externalID)
		collectedCount := countCollectedAccountsFromRows(snapshot.DiscoveredAccounts, setupID)
		candidateCount := countUncollectedCandidatesFromRows(snapshot.DiscoveredAccounts, setupID, current)
		orgUnitRowCount := countOrgUnitRowsFromRows(snapshot.DiscoveredAccounts, setupID)
		if !changes.Empty() {
			plan.Payloads[setupID.String()] = payload
		}
		plan.Setups = append(plan.Setups, plannedSetup{
			SetupID:                   setupID.String(),
			RoleName:                  roleName,
			OrgID:                     orgID,
			ExternalIDConfigured:      externalIDConfigured,
			ExternalIDConsistent:      externalIDConsistent,
			ProxyServerID:             meta.proxyServerID,
			Payload:                   payload,
			ChangeSet:                 changes,
			AddedAccounts:             added,
			RemovedAccounts:           removed,
			ReenabledAccounts:         reenabled,
			DisabledAccounts:          disabled,
			UnchangedAccounts:         unchanged,
			CurrentAccounts:           current,
			DiscoveredAccounts:        toAccountRows(discoveredSet),
			DiscoveredCollectedCount:  collectedCount,
			DiscoveredCandidateCount:  candidateCount,
			DiscoveredOrgUnitRowCount: orgUnitRowCount,
		})
		plan.CandidateChecks = append(plan.CandidateChecks, CandidateCheck{
			SetupID:                setupID.String(),
			ConfiguredAccountCount: len(current),
			NQEAccountRowCount:     len(discoveredRows),
			NQECollectedRowCount:   collectedCount,
			NQECandidateRowCount:   candidateCount,
			NQEOrgUnitRowCount:     orgUnitRowCount,
			Status:                 organizationDiscoveryStatus(candidateCount, orgUnitRowCount),
			Passed:                 organizationDiscoveryVisible(candidateCount, orgUnitRowCount),
			Message:                organizationDiscoveryMessage(candidateCount, orgUnitRowCount),
		})
	}
	if len(plan.Setups) == 0 {
		return nil, fmt.Errorf("no eligible setups found to patch")
	}
	return plan, nil
}

func assertSafeSelectedSetupOwnership(
	currentBySetup map[SetupID]cloudSetupMetadata,
	discoveredBySetup map[SetupID][]DiscoveredAccount,
) error {
	currentOwner := make(map[AccountID]SetupID)
	for setupID, meta := range currentBySetup {
		current, err := adaptCurrentSetup(meta)
		if err != nil {
			return err
		}
		for _, account := range current.Accounts {
			if owner, exists := currentOwner[account.AccountID]; exists && owner != setupID {
				return fmt.Errorf("account %s is currently owned by both selected setups %s and %s", account.AccountID, owner, setupID)
			}
			currentOwner[account.AccountID] = setupID
		}
	}

	desiredOwner := make(map[AccountID]SetupID)
	for setupID, accounts := range discoveredBySetup {
		for _, account := range accounts {
			if owner, exists := desiredOwner[account.AccountID]; exists && owner != setupID {
				return fmt.Errorf("account %s is desired in both selected setups %s and %s", account.AccountID, owner, setupID)
			}
			desiredOwner[account.AccountID] = setupID
			if owner, exists := currentOwner[account.AccountID]; exists && owner != setupID {
				return fmt.Errorf(
					"refusing cross-setup move of account %s from %s to %s: selected setup ownership is unique, but sequential setup PATCHes cannot guarantee a partial apply leaves the account in exactly one setup",
					account.AccountID,
					owner,
					setupID,
				)
			}
		}
	}
	return nil
}

func accountRowsFromChanges(changes []AccountChange, useBefore bool) []accountRow {
	result := make([]accountRow, 0, len(changes))
	for _, change := range changes {
		account := change.After
		if useBefore {
			account = change.Before
		}
		if account == nil {
			continue
		}
		result = append(result, accountRow{
			AccountID:   account.AccountID.String(),
			AccountName: account.AccountName,
		})
	}
	return result
}

func legacyExternalIDAssignments(assignments externalIDBySetupAssignments) externalIDAssignments {
	if len(assignments) == 0 {
		return nil
	}
	result := make(externalIDAssignments, len(assignments))
	for setupID, byAccount := range assignments {
		legacy := make(map[string]string, len(byAccount))
		for accountID, externalID := range byAccount {
			legacy[accountID.String()] = externalID
		}
		result[setupID.String()] = legacy
	}
	return result
}

func extMapToStringMap(assignments map[AccountID]string) map[string]string {
	if len(assignments) == 0 {
		return nil
	}
	result := make(map[string]string, len(assignments))
	for accountID, externalID := range assignments {
		result[accountID.String()] = externalID
	}
	return result
}

func firstSetupID[T any](values map[SetupID]T) (SetupID, bool) {
	if len(values) != 1 {
		return "", false
	}
	for setupID := range values {
		return setupID, true
	}
	return "", false
}

func countCollectedAccountsFromRows(accounts []DiscoveredAccount, setupID SetupID) int {
	count := 0
	for _, account := range accounts {
		if account.SetupID != setupID || !account.CollectedSet {
			continue
		}
		if account.Collected {
			count++
		}
	}
	return count
}

func countUncollectedCandidatesFromRows(accounts []DiscoveredAccount, setupID SetupID, current []accountRow) int {
	currentIDs := make(map[string]bool, len(current))
	for _, account := range current {
		currentIDs[account.AccountID] = true
	}
	count := 0
	for _, account := range accounts {
		if account.SetupID != setupID || !account.CollectedSet {
			continue
		}
		if !account.Collected && !currentIDs[account.AccountID.String()] {
			count++
		}
	}
	return count
}

func countOrgUnitRowsFromRows(accounts []DiscoveredAccount, setupID SetupID) int {
	count := 0
	for _, account := range accounts {
		if account.SetupID != setupID {
			continue
		}
		if account.HasOrganizationalID {
			count++
		}
	}
	return count
}

func toAccountRows(accounts []DiscoveredAccount) []accountRow {
	result := make([]accountRow, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, accountRow{AccountID: account.AccountID.String(), AccountName: account.AccountName})
	}
	return result
}

func mustNewAccountID(value string) AccountID {
	id, _ := NewAccountID(value)
	return id
}

func validateCloudAccountPartitionFromMetadata(account cloudSetupMetadata) error {
	rolePartitions := make(map[string]bool)
	for _, info := range account.assumeRoleInfos {
		parts := strings.Split(strings.TrimSpace(info.RoleArn), ":")
		if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" {
			continue
		}
		partition, err := normalizeAWSPartition(parts[1])
		if err != nil {
			return err
		}
		rolePartitions[partition] = true
	}
	if len(rolePartitions) > 1 {
		partitions := make([]string, 0, len(rolePartitions))
		for partition := range rolePartitions {
			partitions = append(partitions, partition)
		}
		sort.Strings(partitions)
		return fmt.Errorf("mixed IAM role ARN partitions are unsafe: %s", strings.Join(partitions, ", "))
	}
	if len(rolePartitions) == 0 || len(account.regions) == 0 {
		return nil
	}
	var rolePartition string
	for partition := range rolePartitions {
		rolePartition = partition
	}
	regions := make([]string, 0, len(account.regions))
	for region := range account.regions {
		regions = append(regions, region)
	}
	if err := validateRegionsForPartition(regions, rolePartition); err != nil {
		return fmt.Errorf("role ARN partition and configured regions disagree: %w", err)
	}
	return nil
}

type accountRow struct {
	AccountID   string
	AccountName string
}

func mergeDiscoveredWithCurrent(discovered, current []accountRow) []accountRow {
	result := append([]accountRow(nil), discovered...)
	seen := make(map[string]bool, len(result))
	for _, account := range result {
		seen[account.AccountID] = true
	}
	for _, account := range current {
		if seen[account.AccountID] {
			continue
		}
		result = append(result, account)
		seen[account.AccountID] = true
	}
	return result
}

func reenabledAccounts(current []api.AssumeRoleInfo, next []accountRow) []accountRow {
	nextIDs := accountMap(next)
	result := make([]accountRow, 0)
	for _, info := range current {
		accountID := assumeRoleAccountID(info)
		if info.Enabled || accountID == "" {
			continue
		}
		account, ok := nextIDs[accountID]
		if ok {
			result = append(result, account)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].AccountID < result[j].AccountID
	})
	return result
}

func organizationDiscoveryVisible(candidateCount, orgUnitRowCount int) bool {
	return candidateCount > 0 || orgUnitRowCount > 0
}

func organizationDiscoveryMessage(candidateCount, orgUnitRowCount int) string {
	if candidateCount > 0 && orgUnitRowCount > 0 {
		return "uncollected candidate accounts and Organizational Unit IDs are visible in Forward NQE; AWS Organizations discovery appears active"
	}
	if candidateCount > 0 {
		return "uncollected candidate accounts are visible in Forward NQE; AWS Organizations discovery appears active"
	}
	if orgUnitRowCount > 0 {
		return "Organizational Unit IDs are visible in Forward NQE; AWS Organizations discovery appears active"
	}
	return "no uncollected candidate accounts or Organizational Unit IDs are visible in Forward NQE; planned removals require independent AWS Organizations verification and --allow-no-candidates"
}

func organizationDiscoveryStatus(candidateCount, orgUnitRowCount int) string {
	if candidateCount > 0 && orgUnitRowCount > 0 {
		return "visible_candidates_and_ou_ids"
	}
	if candidateCount > 0 {
		return "visible_candidates"
	}
	if orgUnitRowCount > 0 {
		return "visible_ou_ids"
	}
	return "no_org_signal"
}

func dedupeAccounts(accounts []accountRow) []accountRow {
	seen := make(map[string]accountRow)
	order := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if _, ok := seen[account.AccountID]; ok {
			continue
		}
		seen[account.AccountID] = account
		order = append(order, account.AccountID)
	}
	result := make([]accountRow, 0, len(order))
	for _, accountID := range order {
		result = append(result, seen[accountID])
	}
	return result
}

func setupIDSet(setupIDs []string) map[string]bool {
	cleaned := cleanSetupIDs(setupIDs)
	if len(cleaned) == 0 {
		return nil
	}
	result := make(map[string]bool, len(cleaned))
	for _, setupID := range cleaned {
		result[setupID] = true
	}
	return result
}

func cleanSetupIDs(setupIDs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(setupIDs))
	for _, setupID := range setupIDs {
		setupID = strings.TrimSpace(setupID)
		if setupID == "" || seen[setupID] {
			continue
		}
		seen[setupID] = true
		result = append(result, setupID)
	}
	sort.Strings(result)
	return result
}

func extractRoleName(assumeRoleInfos []api.AssumeRoleInfo) string {
	for _, info := range assumeRoleInfos {
		arn := strings.TrimSpace(info.RoleArn)
		if strings.Contains(arn, ":role/") {
			parts := strings.SplitN(arn, ":role/", 2)
			return parts[1]
		}
	}
	return ""
}

func extractRolePartition(assumeRoleInfos []api.AssumeRoleInfo) string {
	for _, info := range assumeRoleInfos {
		parts := strings.Split(strings.TrimSpace(info.RoleArn), ":")
		if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "iam" {
			if partition, err := normalizeAWSPartition(parts[1]); err == nil {
				return partition
			}
		}
	}
	return "aws"
}

func validateCloudAccountPartition(account api.CloudAccount) error {
	rolePartitions := make(map[string]bool)
	for _, info := range account.AssumeRoleInfos {
		parts := strings.Split(strings.TrimSpace(info.RoleArn), ":")
		if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" {
			continue
		}
		partition, err := normalizeAWSPartition(parts[1])
		if err != nil {
			return err
		}
		rolePartitions[partition] = true
	}
	if len(rolePartitions) > 1 {
		partitions := make([]string, 0, len(rolePartitions))
		for partition := range rolePartitions {
			partitions = append(partitions, partition)
		}
		sort.Strings(partitions)
		return fmt.Errorf("mixed IAM role ARN partitions are unsafe: %s", strings.Join(partitions, ", "))
	}
	if len(rolePartitions) == 0 || len(account.Regions) == 0 {
		return nil
	}
	var rolePartition string
	for partition := range rolePartitions {
		rolePartition = partition
	}
	regions := make([]string, 0, len(account.Regions))
	for region := range account.Regions {
		regions = append(regions, region)
	}
	if err := validateRegionsForPartition(regions, rolePartition); err != nil {
		return fmt.Errorf("role ARN partition and configured regions disagree: %w", err)
	}
	return nil
}

func parseOrgID(externalID string) int {
	var orgID int
	if _, err := fmt.Sscanf(strings.TrimSpace(externalID), "Org:%d", &orgID); err == nil {
		return orgID
	}
	return 0
}

func buildAssumeRoleInfos(accounts []accountRow, roleName, externalID string) []api.AssumeRoleInfo {
	return buildAssumeRoleInfosForPartition(accounts, roleName, externalID, "aws")
}

func buildAssumeRoleInfosForPartition(accounts []accountRow, roleName, externalID, partition string) []api.AssumeRoleInfo {
	result := make([]api.AssumeRoleInfo, 0, len(accounts))
	for _, account := range accounts {
		info := api.AssumeRoleInfo{
			AccountID:   account.AccountID,
			AccountName: account.AccountName,
			RoleArn:     roleARN(partition, account.AccountID, roleName),
			Enabled:     true,
		}
		if externalID != "" {
			info.ExternalID = externalID
		}
		result = append(result, info)
	}
	return result
}

func buildAssumeRoleInfosPreservingExternalIDs(
	accounts []accountRow,
	current []api.AssumeRoleInfo,
	roleName string,
	partition string,
	hasUniformOverride bool,
	uniformOverride string,
	assignments map[string]string,
) ([]api.AssumeRoleInfo, error) {
	currentIDs := make(map[string]string, len(current))
	for _, info := range current {
		accountID := assumeRoleAccountID(info)
		if accountID != "" {
			if _, exists := currentIDs[accountID]; exists {
				return nil, fmt.Errorf("current setup contains duplicate account %s", accountID)
			}
			currentIDs[accountID] = strings.TrimSpace(info.ExternalID)
		}
	}
	_, currentConsistent := externalIDState(current)
	currentDefault := ""
	if currentConsistent && len(current) > 0 {
		currentDefault = strings.TrimSpace(current[0].ExternalID)
	}

	nextIDs := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		nextIDs[account.AccountID] = true
	}
	unknownAssignments := make([]string, 0)
	for accountID := range assignments {
		if !nextIDs[accountID] {
			unknownAssignments = append(unknownAssignments, accountID)
		}
	}
	if len(unknownAssignments) > 0 {
		sort.Strings(unknownAssignments)
		return nil, fmt.Errorf("external ID file contains account(s) not present in the discovered inventory: %s", strings.Join(unknownAssignments, ", "))
	}

	result := make([]api.AssumeRoleInfo, 0, len(accounts))
	missingAssignments := make([]string, 0)
	for _, account := range accounts {
		externalID := ""
		if hasUniformOverride {
			externalID = uniformOverride
		} else if assigned, ok := assignments[account.AccountID]; ok {
			externalID = assigned
		} else if existing, ok := currentIDs[account.AccountID]; ok {
			externalID = existing
		} else if currentConsistent {
			externalID = currentDefault
		} else {
			missingAssignments = append(missingAssignments, account.AccountID)
		}
		info := api.AssumeRoleInfo{
			AccountID:   account.AccountID,
			AccountName: account.AccountName,
			RoleArn:     roleARN(partition, account.AccountID, roleName),
			ExternalID:  externalID,
			Enabled:     true,
		}
		result = append(result, info)
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

func roleARN(partition, accountID, roleName string) string {
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName)
}

func currentAccounts(infos []api.AssumeRoleInfo) []accountRow {
	accounts := make([]accountRow, 0, len(infos))
	for _, info := range infos {
		accountID := strings.TrimSpace(info.AccountID)
		if accountID == "" {
			accountID = accountIDFromRoleArn(info.RoleArn)
		}
		if accountID == "" {
			continue
		}
		accountName := strings.TrimSpace(info.AccountName)
		if accountName == "" {
			accountName = accountID
		}
		accounts = append(accounts, accountRow{AccountID: accountID, AccountName: accountName})
	}
	return dedupeAccounts(accounts)
}

func accountIDFromRoleArn(roleArn string) string {
	parts := strings.Split(strings.TrimSpace(roleArn), ":")
	if len(parts) >= 5 && parts[0] == "arn" && parts[2] == "iam" {
		return parts[4]
	}
	return ""
}

func accountDiff(current, next []accountRow) ([]accountRow, []accountRow, []accountRow) {
	currentByID := accountMap(current)
	nextByID := accountMap(next)
	added := make([]accountRow, 0)
	removed := make([]accountRow, 0)
	unchanged := make([]accountRow, 0)
	for _, account := range next {
		if _, ok := currentByID[account.AccountID]; ok {
			unchanged = append(unchanged, account)
			continue
		}
		added = append(added, account)
	}
	for _, account := range current {
		if _, ok := nextByID[account.AccountID]; !ok {
			removed = append(removed, account)
		}
	}
	return added, removed, unchanged
}

func accountMap(accounts []accountRow) map[string]accountRow {
	result := make(map[string]accountRow, len(accounts))
	for _, account := range accounts {
		result[account.AccountID] = account
	}
	return result
}

func accountSummaries(accounts []accountRow) []AccountSummary {
	if len(accounts) == 0 {
		return nil
	}
	result := make([]AccountSummary, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, AccountSummary{AccountID: account.AccountID, AccountName: account.AccountName})
	}
	return result
}

func buildManualPayloads(payloads auditPayloads) map[string][]api.AssumeRoleInfo {
	manual := make(map[string][]api.AssumeRoleInfo, len(payloads))
	for setupID, payload := range payloads {
		if len(payload.AssumeRoleInfos) == 0 {
			manual[setupID] = nil
			continue
		}
		accounts := make([]api.AssumeRoleInfo, len(payload.AssumeRoleInfos))
		copy(accounts, payload.AssumeRoleInfos)
		manual[setupID] = accounts
	}
	return manual
}

func stringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		result[key] = value
	}
	return result
}

func nonEmptyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return values
}

func writeAuditPayloads(path string, payloads auditPayloads) (string, error) {
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode audit payloads: %w", err)
	}
	if err := writeFileAtomic0600(path, data); err != nil {
		return "", fmt.Errorf("write audit payloads: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func buildRollbackPayloads(cloudAccounts []api.CloudAccount, setupIDs []string) (auditPayloads, error) {
	selected := make(map[string]bool, len(setupIDs))
	for _, setupID := range setupIDs {
		selected[setupID] = true
	}
	payloads := make(auditPayloads, len(setupIDs))
	for _, account := range cloudAccounts {
		setupID := strings.TrimSpace(account.Name)
		if !selected[setupID] {
			continue
		}
		regions := make(map[string]int64, len(account.Regions))
		for region, meta := range account.Regions {
			regions[region] = meta.TestInstant
		}
		payloads[setupID] = api.PatchPayload{
			Type:                  account.Type,
			Name:                  setupID,
			Regions:               regions,
			RegionToProxyServerID: stringMap(account.RegionToProxyServerID),
			ProxyServerID:         account.ProxyServerID,
			AssumeRoleInfos:       append([]api.AssumeRoleInfo(nil), account.AssumeRoleInfos...),
		}
	}
	for _, setupID := range setupIDs {
		if _, ok := payloads[setupID]; !ok {
			return nil, fmt.Errorf("cannot build rollback payload: setup %s is no longer present", setupID)
		}
	}
	return payloads, nil
}

func verifyCloudAccountsUnchanged(
	ctx context.Context,
	client *api.Client,
	networkID string,
	setupIDs []string,
	expected auditPayloads,
) error {
	current, err := client.CloudAccounts(ctx, networkID)
	if err != nil {
		return fmt.Errorf("reload cloud setups immediately before apply: %w", err)
	}
	actual, err := buildRollbackPayloads(current, setupIDs)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("selected Forward cloud setup state changed after planning; no PATCH was sent, rerun the dry plan")
	}
	return nil
}

func writeJSONPayload(path string, payload any) (string, string, error) {
	outputPath := strings.TrimSpace(path)
	if outputPath == "" {
		return "", "", nil
	}
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", "", fmt.Errorf("create output directory: %w", err)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode output payload: %w", err)
	}
	if err := writeFileAtomic0600(outputPath, data); err != nil {
		return "", "", fmt.Errorf("write output payload: %w", err)
	}
	return outputPath, fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func writeManualAccountData(path string, accounts []ManualAccountData) (string, string, error) {
	outputPath := strings.TrimSpace(path)
	if outputPath == "" {
		return "", "", nil
	}
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve manual output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", "", fmt.Errorf("create manual output directory: %w", err)
	}
	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode manual account data: %w", err)
	}
	if err := writeFileAtomic0600(outputPath, data); err != nil {
		return "", "", fmt.Errorf("write manual account data: %w", err)
	}
	return outputPath, fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func writeManualPayloads(path string, payloads map[string][]api.AssumeRoleInfo) (string, string, error) {
	outputPath := strings.TrimSpace(path)
	if outputPath == "" {
		return "", "", nil
	}
	outputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve manual output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", "", fmt.Errorf("create manual output directory: %w", err)
	}
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode manual payloads: %w", err)
	}
	if err := writeFileAtomic0600(outputPath, data); err != nil {
		return "", "", fmt.Errorf("write manual payloads: %w", err)
	}
	return outputPath, fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func writeFileAtomic0600(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return err
	}
	return nil
}

func auditPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + ".applied"
	}
	return strings.TrimSuffix(outputPath, ext) + ".applied" + ext
}

func rollbackPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + ".rollback"
	}
	return strings.TrimSuffix(outputPath, ext) + ".rollback" + ext
}
