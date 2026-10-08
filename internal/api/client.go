package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	forward "github.com/forwardnetworks/forward-go-sdk"
)

// PageLimit is the page size for NQE and snapshot listings.
const PageLimit = 1000

const (
	defaultMaxAttempts = 3
	defaultRetryDelay  = 200 * time.Millisecond
	maxRetryDelay      = 5 * time.Second
)

// Client is the only path from awssync to Forward. Every request goes through
// forward-go-sdk; this type narrows it to the calls awssync makes.
type Client struct {
	sdk *forward.Client
}

type QueryAWSAccountsResult struct {
	Items                []map[string]any
	ObservedRowCount     int
	PageLimit            int
	CompletenessUnproven bool
	CompletenessReason   string
}

type SnapshotInfo struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"createdAt,omitempty"`
	State       string `json:"state,omitempty"`
	ProcessedAt string `json:"processedAt,omitempty"`
	Note        string `json:"note,omitempty"`
}

type Network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CloudAccount struct {
	Type                  string                `json:"type,omitempty"`
	Name                  string                `json:"name"`
	ProxyServerID         string                `json:"proxyServerId,omitempty"`
	RegionToProxyServerID map[string]string     `json:"regionToProxyServerId,omitempty"`
	Regions               map[string]RegionMeta `json:"regions,omitempty"`
	AssumeRoleInfos       []AssumeRoleInfo      `json:"assumeRoleInfos,omitempty"`
}

type RegionMeta struct {
	TestInstant int64 `json:"testInstant,omitempty"`
}

type AssumeRoleInfo struct {
	AccountID   string `json:"accountId,omitempty"`
	AccountName string `json:"accountName,omitempty"`
	RoleArn     string `json:"roleArn,omitempty"`
	ExternalID  string `json:"externalId,omitempty"`
	ErrorMsg    string `json:"errorMsg,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type PatchPayload struct {
	Type                  string            `json:"type"`
	Name                  string            `json:"name"`
	Regions               map[string]int64  `json:"regions,omitempty"`
	RegionToProxyServerID map[string]string `json:"regionToProxyServerId"`
	ProxyServerID         string            `json:"proxyServerId,omitempty"`
	AssumeRoleInfos       []AssumeRoleInfo  `json:"assumeRoleInfos"`
}

type CreateAWSPayload struct {
	Type                          string            `json:"type"`
	Name                          string            `json:"name"`
	Collect                       bool              `json:"collect"`
	Username                      string            `json:"username,omitempty"`
	Password                      string            `json:"password,omitempty"`
	Regions                       map[string]int64  `json:"regions"`
	ProxyServerID                 string            `json:"proxyServerId,omitempty"`
	RegionToProxyServerID         map[string]string `json:"regionToProxyServerId,omitempty"`
	AssumeRoleInfos               []AssumeRoleInfo  `json:"assumeRoleInfos,omitempty"`
	UseForwardAccountToAssumeRole *bool             `json:"useForwardAccountToAssumeRole,omitempty"`
}

type ExternalIDResponse struct {
	ExternalID string `json:"externalId"`
}

type Webhook struct {
	Name                 string             `json:"name"`
	Description          string             `json:"description,omitempty"`
	URL                  string             `json:"url"`
	DisableSSLValidation bool               `json:"disableSslValidation,omitempty"`
	EventParams          WebhookEventParams `json:"eventParams"`
	Credential           *WebhookBasicAuth  `json:"credential,omitempty"`
	Enabled              bool               `json:"enabled"`
	Template             WebhookTemplate    `json:"template"`
}

type WebhookEventParams struct {
	Type       string   `json:"type"`
	NetworkIDs []string `json:"networkIds"`
}

type WebhookBasicAuth struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type WebhookTemplate struct {
	PayloadFormat string `json:"payloadFormat"`
	Template      string `json:"template"`
}

type WebhookTestResult struct {
	Instant int64  `json:"instant,omitempty"`
	Error   string `json:"error,omitempty"`
}

func NewClient(host, apiPrefix, username, password string, insecure bool, timeout time.Duration) (*Client, error) {
	if prefix := strings.Trim(strings.TrimSpace(apiPrefix), "/"); prefix != "" && prefix != "api" {
		return nil, fmt.Errorf("API prefix %q is not supported: forward-go-sdk always uses /api", apiPrefix)
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("host is required")
	}
	if !strings.Contains(host, "://") {
		host = "https://" + strings.TrimSpace(host)
	}
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("password is required")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	sdk, err := forward.NewClient(forward.Config{
		BaseURL:            host,
		Username:           username,
		Password:           password,
		UserAgent:          "awssync",
		InsecureSkipVerify: insecure,
		HTTPClient:         &http.Client{Timeout: timeout},
		Retry: forward.RetryPolicy{
			MaxAttempts: defaultMaxAttempts,
			Delay:       defaultRetryDelay,
			MaxDelay:    maxRetryDelay,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Client{sdk: sdk}, nil
}

// IsHTTPStatus reports whether err is a Forward response with one of the codes.
func IsHTTPStatus(err error, statusCodes ...int) bool {
	for _, code := range statusCodes {
		if forward.IsStatus(err, code) {
			return true
		}
	}
	return false
}

// IsDuplicateWebhookError reports whether Forward refused a webhook create
// because one with that name already exists.
func IsDuplicateWebhookError(err error) bool {
	if !IsHTTPStatus(err, http.StatusBadRequest, http.StatusConflict) {
		return false
	}
	var response *forward.ErrorResponse
	if !errors.As(err, &response) {
		return false
	}
	text := strings.ToLower(response.Message + " " + response.Reason + " " + string(response.Body))
	return strings.Contains(text, "duplicate") || strings.Contains(text, "already")
}

func (c *Client) QueryAWSAccounts(
	ctx context.Context,
	networkID, snapshotID, query, queryID string,
	parameters map[string]any,
	setupIDs []string,
) ([]map[string]any, error) {
	result, err := c.QueryAWSAccountsWithMetadata(ctx, networkID, snapshotID, query, queryID, parameters, setupIDs)
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

func (c *Client) QueryAWSAccountsWithMetadata(
	ctx context.Context,
	networkID, snapshotID, query, queryID string,
	parameters map[string]any,
	setupIDs []string,
) (QueryAWSAccountsResult, error) {
	if strings.TrimSpace(networkID) == "" {
		return QueryAWSAccountsResult{}, fmt.Errorf("network ID is required")
	}
	query = strings.TrimSpace(query)
	queryID = strings.TrimSpace(queryID)
	if query == "" && queryID == "" {
		return QueryAWSAccountsResult{}, fmt.Errorf("query or query ID is required")
	}
	setupIDs = cleanSetupIDs(setupIDs)
	var allItems []map[string]any
	var previousPageSignature string
	var completenessUnproven bool
	completenessReason := "NQE pagination returned a terminating short page"
	for offset := 0; ; offset += PageLimit {
		filters := []forward.NQEColumnFilter{{
			ColumnName: "Cloud Type",
			Operator:   forward.NQEFilterDefault,
			Value:      "AWS",
		}}
		if len(setupIDs) == 1 {
			filters = append(filters, forward.NQEColumnFilter{
				ColumnName: "Cloud Setup ID",
				Operator:   forward.NQEFilterDefault,
				Value:      setupIDs[0],
			})
		}
		pageOffset, pageLimit := int32(offset), int32(PageLimit)
		result, _, err := c.sdk.NQE.Run(ctx, networkID, strings.TrimSpace(snapshotID), forward.NQEQueryRequest{
			Query:      query,
			QueryID:    queryID,
			Parameters: parameters,
			Options: &forward.NQEOptions{
				Offset:        &pageOffset,
				Limit:         &pageLimit,
				ColumnFilters: filters,
			},
		})
		if err != nil {
			return QueryAWSAccountsResult{}, err
		}
		rows, err := result.RowsAny()
		if err != nil {
			return QueryAWSAccountsResult{}, err
		}
		pageSignature := nqePageSignature(rows)
		if len(rows) > 0 && pageSignature == previousPageSignature {
			completenessUnproven = true
			completenessReason = "NQE pagination returned a repeated page; the offset cursor did not advance the result window"
			break
		}
		previousPageSignature = pageSignature
		allItems = append(allItems, filterItemsBySetupID(rows, setupIDs)...)
		if len(rows) < PageLimit {
			break
		}
	}
	if len(allItems) > 0 && len(allItems)%PageLimit == 0 && !completenessUnproven {
		completenessUnproven = true
		completenessReason = "NQE result count is an exact multiple of PageLimit, so truncation cannot be ruled out"
	}
	return QueryAWSAccountsResult{
		Items:                allItems,
		ObservedRowCount:     len(allItems),
		PageLimit:            PageLimit,
		CompletenessUnproven: completenessUnproven,
		CompletenessReason:   completenessReason,
	}, nil
}

func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	networks, _, err := c.sdk.Networks.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]Network, 0, len(networks))
	for _, network := range networks {
		result = append(result, Network{ID: string(network.ID), Name: network.Name})
	}
	return result, nil
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
	return result
}

func filterItemsBySetupID(items []map[string]any, setupIDs []string) []map[string]any {
	if len(setupIDs) <= 1 {
		return items
	}
	allowed := make(map[string]bool, len(setupIDs))
	for _, setupID := range setupIDs {
		allowed[setupID] = true
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		setupID, _ := item["Cloud Setup ID"].(string)
		if allowed[strings.TrimSpace(setupID)] {
			result = append(result, item)
		}
	}
	return result
}

func nqePageSignature(items []map[string]any) string {
	if len(items) == 0 {
		return ""
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return fmt.Sprintf("%#v", items)
	}
	return string(encoded)
}

func snapshotInfo(snapshot forward.Snapshot) SnapshotInfo {
	return SnapshotInfo{
		ID:          string(snapshot.ID),
		CreatedAt:   snapshot.CreatedAt,
		State:       snapshot.State,
		ProcessedAt: snapshot.ProcessedAt,
		Note:        snapshot.Note,
	}
}

func (c *Client) LatestProcessedSnapshot(ctx context.Context, networkID string) (*SnapshotInfo, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	snapshot, _, err := c.sdk.Snapshots.LatestProcessed(ctx, networkID)
	if err != nil {
		return nil, err
	}
	info := snapshotInfo(*snapshot)
	if strings.TrimSpace(info.ID) == "" {
		return nil, fmt.Errorf("latest snapshot response did not include an id")
	}
	return &info, nil
}

func (c *Client) ListSnapshots(ctx context.Context, networkID string) ([]SnapshotInfo, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	includeArchived := true
	snapshots, _, err := c.sdk.Snapshots.List(ctx, networkID, forward.SnapshotListOptions{IncludeArchived: &includeArchived})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(snapshots))
	result := make([]SnapshotInfo, 0, len(snapshots))
	for _, snapshot := range snapshots {
		info := snapshotInfo(snapshot)
		if strings.TrimSpace(info.ID) == "" {
			continue
		}
		if seen[info.ID] {
			return nil, fmt.Errorf("list snapshots returned snapshot %s more than once", info.ID)
		}
		seen[info.ID] = true
		result = append(result, info)
	}
	return result, nil
}

func (c *Client) CloudAccounts(ctx context.Context, networkID string) ([]CloudAccount, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	accounts, _, err := c.sdk.CloudAccounts.List(ctx, networkID)
	if err != nil {
		return nil, err
	}
	result := make([]CloudAccount, 0, len(accounts))
	for _, account := range accounts {
		converted := CloudAccount{
			Type:                  account.Type,
			Name:                  account.Name,
			ProxyServerID:         account.ProxyServerID,
			RegionToProxyServerID: account.RegionToProxyServerID,
		}
		if len(account.Regions) > 0 {
			converted.Regions = make(map[string]RegionMeta, len(account.Regions))
			for name, region := range account.Regions {
				converted.Regions[name] = RegionMeta{TestInstant: region.TestInstant}
			}
		}
		for _, role := range account.AssumeRoleInfos {
			converted.AssumeRoleInfos = append(converted.AssumeRoleInfos, AssumeRoleInfo{
				AccountID:   role.AccountID,
				AccountName: role.AccountName,
				RoleArn:     role.RoleARN,
				ExternalID:  role.ExternalID,
				ErrorMsg:    role.ErrorMsg,
				Enabled:     role.Enabled,
			})
		}
		result = append(result, converted)
	}
	return result, nil
}

func (c *Client) PatchCloudAccount(ctx context.Context, networkID, setupID string, payload PatchPayload) error {
	if strings.TrimSpace(networkID) == "" {
		return fmt.Errorf("network ID is required")
	}
	if strings.TrimSpace(setupID) == "" {
		return fmt.Errorf("setup ID is required")
	}
	name := payload.Name
	roles := sdkRoles(payload.AssumeRoleInfos)
	if roles == nil {
		roles = []forward.AWSAssumeRoleInfo{}
	}
	patch := forward.CloudAccountPatch{
		Type:                  payload.Type,
		Name:                  &name,
		Regions:               payload.Regions,
		RegionToProxyServerID: payload.RegionToProxyServerID,
		AssumeRoleInfos:       &roles,
	}
	if payload.ProxyServerID != "" {
		proxy := payload.ProxyServerID
		patch.ProxyServerID = &proxy
	}
	_, _, err := c.sdk.CloudAccounts.Patch(ctx, networkID, setupID, patch)
	return err
}

func (c *Client) CreateCloudAccount(ctx context.Context, networkID string, payload CreateAWSPayload) error {
	if strings.TrimSpace(networkID) == "" {
		return fmt.Errorf("network ID is required")
	}
	request := forward.CloudAccountRequest{
		Type:                          payload.Type,
		Name:                          payload.Name,
		Collect:                       payload.Collect,
		Username:                      payload.Username,
		Password:                      payload.Password,
		ProxyServerID:                 payload.ProxyServerID,
		RegionToProxyServerID:         payload.RegionToProxyServerID,
		AssumeRoleInfos:               sdkRoles(payload.AssumeRoleInfos),
		UseForwardAccountToAssumeRole: payload.UseForwardAccountToAssumeRole,
	}
	if payload.Regions != nil {
		request.Regions = make(map[string]int, len(payload.Regions))
		for name, instant := range payload.Regions {
			request.Regions[name] = int(instant)
		}
	}
	_, _, err := c.sdk.CloudAccounts.Create(ctx, networkID, request)
	return err
}

func sdkRoles(roles []AssumeRoleInfo) []forward.AWSAssumeRoleInfo {
	if roles == nil {
		return nil
	}
	result := make([]forward.AWSAssumeRoleInfo, 0, len(roles))
	for _, role := range roles {
		result = append(result, forward.AWSAssumeRoleInfo{
			AccountID:   role.AccountID,
			AccountName: role.AccountName,
			RoleARN:     role.RoleArn,
			ExternalID:  role.ExternalID,
			Enabled:     role.Enabled,
			ErrorMsg:    role.ErrorMsg,
		})
	}
	return result
}

func (c *Client) AWSAssumeRoleExternalID(ctx context.Context, networkID string) (string, error) {
	if strings.TrimSpace(networkID) == "" {
		return "", fmt.Errorf("network ID is required")
	}
	externalID, _, err := c.sdk.CloudAccounts.AWSAssumeRoleExternalID(ctx, networkID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(externalID), nil
}

func (c *Client) AddWebhook(ctx context.Context, webhook Webhook) error {
	request, err := webhookRequest(webhook)
	if err != nil {
		return err
	}
	_, err = c.sdk.Webhooks.Create(ctx, request)
	return err
}

func (c *Client) UpdateWebhook(ctx context.Context, name string, webhook Webhook) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("webhook name is required")
	}
	request, err := webhookRequest(webhook)
	if err != nil {
		return err
	}
	patch := forward.WebhookPatch{
		Name:                 &request.Name,
		Description:          &request.Description,
		URL:                  &request.URL,
		DisableSSLValidation: &request.DisableSSLValidation,
		EventParams:          request.EventParams,
		Credential:           request.Credential,
		Enabled:              request.Enabled,
		Template:             request.Template,
	}
	_, err = c.sdk.Webhooks.Update(ctx, name, patch)
	return err
}

func (c *Client) TestNewWebhook(ctx context.Context, webhook Webhook) (*WebhookTestResult, error) {
	request, err := webhookRequest(webhook)
	if err != nil {
		return nil, err
	}
	raw, _, err := c.sdk.Webhooks.TestNew(ctx, request)
	if err != nil {
		return nil, err
	}
	var result WebhookTestResult
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("decode webhook test result: %w", err)
		}
	}
	return &result, nil
}

func webhookRequest(webhook Webhook) (forward.WebhookRequest, error) {
	template, err := json.Marshal(webhook.Template)
	if err != nil {
		return forward.WebhookRequest{}, fmt.Errorf("encode webhook template: %w", err)
	}
	networkIDs := webhook.EventParams.NetworkIDs
	if networkIDs == nil {
		networkIDs = []string{}
	}
	enabled := webhook.Enabled
	request := forward.WebhookRequest{
		Name:                 webhook.Name,
		Description:          webhook.Description,
		URL:                  webhook.URL,
		DisableSSLValidation: webhook.DisableSSLValidation,
		EventParams: map[string]any{
			"type":       webhook.EventParams.Type,
			"networkIds": networkIDs,
		},
		Template: template,
		Enabled:  &enabled,
	}
	if webhook.Credential != nil {
		request.Credential = &forward.WebhookCredentialRequest{
			Type:     webhook.Credential.Type,
			Username: webhook.Credential.Username,
			Password: webhook.Credential.Password,
		}
	}
	return request, nil
}
