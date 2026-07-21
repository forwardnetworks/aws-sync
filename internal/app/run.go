package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Host               string
	Username           string
	Password           string
	NetworkID          string
	SnapshotID         string
	Query              string
	QueryID            string
	QuerySetupParam    string
	SetupIDs           []string
	Output             string
	ManualOutput       string
	APIPrefix          string
	Insecure           bool
	Timeout            time.Duration
	Apply              bool
	AllowRemovals      bool
	AllowNoCandidates  bool
	AllowNoOrgEvidence bool
	MaxSnapshotAge     time.Duration
	Source             string
	AuthoritativeInput bool
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
	Apply               bool                            `json:"apply"`
	FetchedItemCount    int                             `json:"fetched_item_count"`
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
	UnchangedAccountCount        int               `json:"unchanged_account_count"`
	Patched                      bool              `json:"patched"`
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
	client, err := api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	networkID, err := ResolveNetworkID(ctx, client, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	cfg.NetworkID = networkID
	if err := validateSnapshotFreshness(ctx, client, cfg); err != nil {
		return nil, err
	}
	if err := validateQuerySetupParam(cfg); err != nil {
		return nil, err
	}
	query, queryID, parameters := queryInputs(cfg)
	items, err := client.QueryAWSAccounts(ctx, cfg.NetworkID, cfg.SnapshotID, query, queryID, parameters, cfg.SetupIDs)
	if err != nil {
		return nil, err
	}
	cloudAccounts, err := client.CloudAccounts(ctx, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	return runPlannedSync(ctx, cfg, client, items, cloudAccounts)
}

func runPlannedSync(
	ctx context.Context,
	cfg Config,
	client *api.Client,
	items []map[string]any,
	cloudAccounts []api.CloudAccount,
) (*Summary, error) {
	plan, err := buildPlan(items, cloudAccounts, cfg.QueryID, cfg.SetupIDs)
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

	summary := buildSummary(
		cfg,
		outputPath,
		payloadSHA256,
		manualOutputPath,
		manualPayloadSHA256,
		manualPayloadsForSummary,
		len(items),
		plan,
		0,
	)
	if cfg.Apply && plan.HasRemovals() && !cfg.AllowRemovals {
		summary.RemovalBlocked = true
		return summary, fmt.Errorf("planned account removals require --allow-removals")
	}
	if cfg.Apply && !cfg.AuthoritativeInput && plan.HasCandidateRemovalRisk() && !cfg.AllowNoCandidates {
		summary.RemovalBlocked = true
		return summary, fmt.Errorf("planned removals with no uncollected candidate accounts visible require --allow-no-candidates")
	}
	if cfg.Apply && !cfg.AuthoritativeInput && plan.HasGovCloudRemovalsWithoutOrganizationEvidence() {
		summary.RemovalBlocked = true
		return summary, fmt.Errorf("GovCloud account removals require positive AWS Organizations evidence; use sync-accounts with an authoritative reviewed manifest when Organizations is unavailable")
	}
	if cfg.Apply && !cfg.AuthoritativeInput && plan.HasNoOrganizationEvidenceForRemovals() && !cfg.AllowNoOrgEvidence {
		missingSetups := strings.Join(plan.setupsWithoutOrganizationEvidenceForRemovals(), ", ")
		summary.RemovalBlocked = true
		return summary, fmt.Errorf("planned removals with no AWS Organizations evidence in NQE for setup(s): %s require --allow-no-org-evidence", missingSetups)
	}

	if cfg.Apply {
		if _, err := writeAuditPayloads(auditPath(outputPath), plan.Payloads); err != nil {
			return nil, err
		}
	}
	patchedCount, err := applyPlan(ctx, cfg, client, plan)
	if err != nil {
		return nil, err
	}
	return buildSummary(
		cfg,
		outputPath,
		payloadSHA256,
		manualOutputPath,
		manualPayloadSHA256,
		manualPayloadsForSummary,
		len(items),
		plan,
		patchedCount,
	), nil
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

func applyPlan(ctx context.Context, cfg Config, client *api.Client, plan *patchPlan) (int, error) {
	if !cfg.Apply {
		return 0, nil
	}
	patchedCount := 0
	for _, setup := range plan.Setups {
		if err := client.PatchCloudAccount(ctx, cfg.NetworkID, setup.SetupID, setup.Payload); err != nil {
			return patchedCount, fmt.Errorf("patch setup %s: %w", setup.SetupID, err)
		}
		patchedCount++
	}
	return patchedCount, nil
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
		if cfg.AuthoritativeInput {
			discoverySignal = "account_manifest"
			discoveryMessage = "Account inventory came from the explicitly reviewed manifest; AWS Organizations was not queried"
		}
		setupSummaries = append(setupSummaries, SetupSummary{
			SetupID:                      setup.SetupID,
			RoleName:                     setup.RoleName,
			OrgID:                        setup.OrgID,
			ExternalIDConfigured:         setup.ExternalIDConfigured,
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
			UnchangedAccountCount:        len(setup.UnchangedAccounts),
			Patched:                      cfg.Apply,
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
		PlannedSetupCount:   len(plan.Setups),
		PatchedSetupCount:   patchedCount,
		SkippedSetupCount:   len(plan.Skips),
		PlannedSetups:       setupSummaries,
		SkippedSetups:       plan.Skips,
		CandidateCheck:      plan.CandidateChecks,
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
}

type plannedSetup struct {
	SetupID                   string
	RoleName                  string
	OrgID                     int
	ExternalIDConfigured      bool
	ProxyServerID             string
	Payload                   api.PatchPayload
	AddedAccounts             []accountRow
	RemovedAccounts           []accountRow
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
	RoleNameBySetup   map[string]string
	ExternalIDBySetup map[string]string
}

func buildPlan(items []map[string]any, cloudAccounts []api.CloudAccount, queryID string, requestedSetupIDs []string) (*patchPlan, error) {
	return buildPlanWithOptions(items, cloudAccounts, queryID, requestedSetupIDs, buildPlanOptions{})
}

func buildPlanWithOptions(items []map[string]any, cloudAccounts []api.CloudAccount, _ string, requestedSetupIDs []string, opts buildPlanOptions) (*patchPlan, error) {
	cloudMetaMap := cloudAccountMetaMap(cloudAccounts, requestedSetupIDs)
	if len(cloudMetaMap) == 0 {
		return nil, fmt.Errorf("no cloud account metadata available in Forward")
	}
	groupedAccounts := groupAccountsBySetup(items)
	if len(groupedAccounts) == 0 {
		fallbackSetupID, fallbackAccounts := fallbackAccounts(items, cloudMetaMap)
		if fallbackSetupID != "" && len(fallbackAccounts) > 0 {
			groupedAccounts = map[string][]accountRow{fallbackSetupID: fallbackAccounts}
		}
	}
	if len(groupedAccounts) == 0 {
		if len(cloudMetaMap) > 1 && hasAccountRows(items) {
			return nil, fmt.Errorf("NQE response has AWS accounts but no setup ID data; pass --query-id only if overriding the platform query")
		}
		return nil, fmt.Errorf("no AWS accounts found in query response")
	}

	plannedSetupIDs := make([]string, 0, len(groupedAccounts))
	for setupID := range groupedAccounts {
		plannedSetupIDs = append(plannedSetupIDs, setupID)
	}
	sort.Strings(plannedSetupIDs)

	plan := &patchPlan{Payloads: make(auditPayloads)}
	for _, setupID := range plannedSetupIDs {
		meta, ok := cloudMetaMap[setupID]
		if !ok {
			plan.Skips = append(plan.Skips, SkipSummary{SetupID: setupID, Reason: "setup metadata not found in Forward"})
			continue
		}
		if err := validateCloudAccountPartition(meta); err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		roleName := extractRoleName(meta.AssumeRoleInfos)
		if override := strings.TrimSpace(opts.RoleNameBySetup[setupID]); override != "" {
			roleName = override
		}
		if roleName == "" {
			plan.Skips = append(plan.Skips, SkipSummary{SetupID: setupID, Reason: "unable to determine role ARN name from assumeRoleInfos"})
			continue
		}
		externalID := extractExternalID(meta.AssumeRoleInfos)
		if override, ok := opts.ExternalIDBySetup[setupID]; ok {
			externalID = strings.TrimSpace(override)
		}
		orgID := parseOrgID(externalID)
		partition := extractRolePartition(meta.AssumeRoleInfos)
		nextAccounts := groupedAccounts[setupID]
		current := currentAccounts(meta.AssumeRoleInfos)
		payload := api.PatchPayload{
			Type:                  "AWS",
			Name:                  setupID,
			Regions:               regionMap(meta.Regions),
			RegionToProxyServerID: stringMap(meta.RegionToProxyServerID),
			AssumeRoleInfos:       buildAssumeRoleInfosForPartition(nextAccounts, roleName, externalID, partition),
		}
		if strings.TrimSpace(meta.ProxyServerID) != "" {
			payload.ProxyServerID = meta.ProxyServerID
		}
		added, removed, unchanged := accountDiff(current, nextAccounts)
		collectedCount := countCollectedAccounts(items, setupID)
		candidateCount := countUncollectedCandidates(items, setupID)
		orgUnitRowCount := countOrgUnitRows(items, setupID)
		plan.Payloads[setupID] = payload
		plan.Setups = append(plan.Setups, plannedSetup{
			SetupID:                   setupID,
			RoleName:                  roleName,
			OrgID:                     orgID,
			ExternalIDConfigured:      externalID != "",
			ProxyServerID:             meta.ProxyServerID,
			Payload:                   payload,
			AddedAccounts:             added,
			RemovedAccounts:           removed,
			UnchangedAccounts:         unchanged,
			CurrentAccounts:           current,
			DiscoveredAccounts:        nextAccounts,
			DiscoveredCollectedCount:  collectedCount,
			DiscoveredCandidateCount:  candidateCount,
			DiscoveredOrgUnitRowCount: orgUnitRowCount,
		})
		plan.CandidateChecks = append(plan.CandidateChecks, CandidateCheck{
			SetupID:                setupID,
			ConfiguredAccountCount: len(current),
			NQEAccountRowCount:     len(nextAccounts),
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

func countCollectedAccounts(items []map[string]any, setupID string) int {
	count := 0
	for _, item := range items {
		if itemSetupID(item) != setupID {
			continue
		}
		collected, ok := boolValue(item["Collected?"])
		if ok && collected {
			count++
		}
	}
	return count
}

type accountRow struct {
	AccountID   string
	AccountName string
}

func groupAccountsBySetup(items []map[string]any) map[string][]accountRow {
	grouped := make(map[string][]accountRow)
	for _, item := range items {
		setupID := stringValue(item["Cloud Setup ID"])
		if setupID == "" {
			setupID = stringValue(item["Setup ID"])
		}
		if setupID == "" {
			setupID = stringValue(item["Cloud Account Setup ID"])
		}
		if setupID == "" {
			setupID = stringValue(item["Cloud Account Setup"])
		}
		accountID := stringValue(item["Cloud Account ID"])
		if setupID == "" || accountID == "" {
			continue
		}
		accountName := stringValue(item["Cloud Account Name"])
		if accountName == "" {
			accountName = accountID
		}
		grouped[setupID] = append(grouped[setupID], accountRow{AccountID: accountID, AccountName: accountName})
	}
	for setupID := range grouped {
		grouped[setupID] = dedupeAccounts(grouped[setupID])
	}
	return grouped
}

func fallbackAccounts(items []map[string]any, cloudMetaMap map[string]api.CloudAccount) (string, []accountRow) {
	if len(cloudMetaMap) != 1 {
		return "", nil
	}
	var setupID string
	for key := range cloudMetaMap {
		setupID = key
	}
	accounts := make([]accountRow, 0, len(items))
	for _, item := range items {
		accountID := stringValue(item["Cloud Account ID"])
		if accountID == "" {
			continue
		}
		accountName := stringValue(item["Cloud Account Name"])
		if accountName == "" {
			accountName = accountID
		}
		accounts = append(accounts, accountRow{AccountID: accountID, AccountName: accountName})
	}
	return setupID, dedupeAccounts(accounts)
}

func hasAccountRows(items []map[string]any) bool {
	for _, item := range items {
		if stringValue(item["Cloud Account ID"]) != "" {
			return true
		}
	}
	return false
}

func countUncollectedCandidates(items []map[string]any, setupID string) int {
	count := 0
	for _, item := range items {
		if itemSetupID(item) != setupID {
			continue
		}
		collected, ok := boolValue(item["Collected?"])
		if ok && !collected {
			count++
		}
	}
	return count
}

func countOrgUnitRows(items []map[string]any, setupID string) int {
	count := 0
	for _, item := range items {
		if itemSetupID(item) != setupID {
			continue
		}
		if hasOrgUnitIDs(item["Organizational Unit IDs"]) {
			count++
		}
	}
	return count
}

func hasOrgUnitIDs(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case string:
		return strings.TrimSpace(typed) != "" && strings.TrimSpace(typed) != "[]"
	default:
		return false
	}
}

func itemSetupID(item map[string]any) string {
	for _, key := range []string{"Cloud Setup ID", "Setup ID", "Cloud Account Setup ID", "Cloud Account Setup"} {
		if setupID := stringValue(item[key]); setupID != "" {
			return setupID
		}
	}
	return ""
}

func boolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes":
			return true, true
		case "false", "no":
			return false, true
		}
	}
	return false, false
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

func cloudAccountMetaMap(cloudAccounts []api.CloudAccount, setupIDs []string) map[string]api.CloudAccount {
	allowed := setupIDSet(setupIDs)
	result := make(map[string]api.CloudAccount)
	for _, account := range cloudAccounts {
		accountType := strings.ToUpper(strings.TrimSpace(account.Type))
		if accountType != "" && accountType != "AWS" {
			continue
		}
		setupID := strings.TrimSpace(account.Name)
		if setupID == "" {
			continue
		}
		if len(allowed) > 0 && !allowed[setupID] {
			continue
		}
		result[setupID] = account
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

func extractExternalID(assumeRoleInfos []api.AssumeRoleInfo) string {
	for _, info := range assumeRoleInfos {
		extID := strings.TrimSpace(info.ExternalID)
		if extID != "" {
			return extID
		}
	}
	return ""
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

func regionMap(regions map[string]api.RegionMeta) map[string]int64 {
	result := make(map[string]int64, len(regions))
	currentEpochMs := time.Now().UnixMilli()
	for region, meta := range regions {
		if meta.TestInstant != 0 {
			result[region] = meta.TestInstant
			continue
		}
		result[region] = currentEpochMs
	}
	return result
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

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func writeAuditPayloads(path string, payloads auditPayloads) (string, error) {
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode audit payloads: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write audit payloads: %w", err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
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
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
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
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
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
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return "", "", fmt.Errorf("write manual payloads: %w", err)
	}
	return outputPath, fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func auditPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	if ext == "" {
		return outputPath + ".applied"
	}
	return strings.TrimSuffix(outputPath, ext) + ".applied" + ext
}
