package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const PageLimit = 1000

type Client struct {
	baseURL    *url.URL
	apiPrefix  string
	username   string
	password   string
	httpClient *http.Client
}

type NQEResponse struct {
	Items []map[string]any `json:"items"`
}

type QueryRequest struct {
	Query        string         `json:"query,omitempty"`
	QueryID      string         `json:"queryId,omitempty"`
	QueryOptions QueryOptions   `json:"queryOptions"`
	Parameters   map[string]any `json:"parameters,omitempty"`
}

type QueryOptions struct {
	Offset        int            `json:"offset"`
	Limit         int            `json:"limit"`
	ColumnFilters []ColumnFilter `json:"columnFilters,omitempty"`
}

type SnapshotInfo struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"createdAt,omitempty"`
	State       string `json:"state,omitempty"`
	ProcessedAt string `json:"processedAt,omitempty"`
	Note        string `json:"note,omitempty"`
}

type NetworkSnapshots struct {
	Snapshots []SnapshotInfo `json:"snapshots"`
}

type Network struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ColumnFilter struct {
	ColumnName string `json:"columnName"`
	Value      string `json:"value"`
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

type HTTPError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s failed with status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

func IsHTTPStatus(err error, statusCodes ...int) bool {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	for _, statusCode := range statusCodes {
		if httpErr.StatusCode == statusCode {
			return true
		}
	}
	return false
}

func IsDuplicateWebhookError(err error) bool {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	if httpErr.StatusCode != http.StatusBadRequest && httpErr.StatusCode != http.StatusConflict {
		return false
	}
	body := strings.ToLower(httpErr.Body)
	return strings.Contains(body, "duplicate") || strings.Contains(body, "already")
}

func NewClient(host, apiPrefix, username, password string, insecure bool, timeout time.Duration) (*Client, error) {
	baseURL, err := normalizeHost(host)
	if err != nil {
		return nil, err
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = insecure //nolint:gosec

	return &Client{
		baseURL:   baseURL,
		apiPrefix: normalizeAPIPrefix(apiPrefix),
		username:  username,
		password:  password,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

func (c *Client) QueryAWSAccounts(
	ctx context.Context,
	networkID, snapshotID, query, queryID string,
	parameters map[string]any,
	setupIDs []string,
) ([]map[string]any, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	query = strings.TrimSpace(query)
	queryID = strings.TrimSpace(queryID)
	if query == "" && queryID == "" {
		return nil, fmt.Errorf("query or query ID is required")
	}
	setupIDs = cleanSetupIDs(setupIDs)
	var allItems []map[string]any
	for offset := 0; ; offset += PageLimit {
		columnFilters := []ColumnFilter{{
			ColumnName: "Cloud Type",
			Value:      "AWS",
		}}
		if len(setupIDs) == 1 {
			columnFilters = append(columnFilters, ColumnFilter{
				ColumnName: "Cloud Setup ID",
				Value:      setupIDs[0],
			})
		}
		payload := QueryRequest{
			Query:      query,
			QueryID:    queryID,
			Parameters: parameters,
			QueryOptions: QueryOptions{
				Offset:        offset,
				Limit:         PageLimit,
				ColumnFilters: columnFilters,
			},
		}
		var response NQEResponse
		endpointPath := fmt.Sprintf("/nqe?networkId=%s", url.QueryEscape(networkID))
		if strings.TrimSpace(snapshotID) != "" {
			endpointPath += fmt.Sprintf("&snapshotId=%s", url.QueryEscape(snapshotID))
		}
		if err := c.doJSON(ctx, http.MethodPost, endpointPath, payload, &response); err != nil {
			return nil, err
		}
		allItems = append(allItems, filterItemsBySetupID(response.Items, setupIDs)...)
		if len(response.Items) < PageLimit {
			break
		}
	}
	return allItems, nil
}

func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var networks []Network
	if err := c.doJSON(ctx, http.MethodGet, "/networks", nil, &networks); err != nil {
		return nil, err
	}
	return networks, nil
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

func (c *Client) LatestProcessedSnapshot(ctx context.Context, networkID string) (*SnapshotInfo, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	var snapshot SnapshotInfo
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/networks/%s/snapshots/latestProcessed", networkID), nil, &snapshot); err != nil {
		return nil, err
	}
	if strings.TrimSpace(snapshot.ID) == "" {
		return nil, fmt.Errorf("latest snapshot response did not include an id")
	}
	return &snapshot, nil
}

func (c *Client) ListSnapshots(ctx context.Context, networkID string) ([]SnapshotInfo, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	var snapshots NetworkSnapshots
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/networks/%s/snapshots?includeArchived=true", networkID), nil, &snapshots); err != nil {
		return nil, err
	}
	return snapshots.Snapshots, nil
}
func (c *Client) CloudAccounts(ctx context.Context, networkID string) ([]CloudAccount, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network ID is required")
	}
	var accounts []CloudAccount
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/networks/%s/cloudAccounts", networkID), nil, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (c *Client) PatchCloudAccount(ctx context.Context, networkID, setupID string, payload any) error {
	if strings.TrimSpace(networkID) == "" {
		return fmt.Errorf("network ID is required")
	}
	if strings.TrimSpace(setupID) == "" {
		return fmt.Errorf("setup ID is required")
	}
	return c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/networks/%s/cloudAccounts/%s", networkID, setupID), payload, nil)
}

func (c *Client) CreateCloudAccount(ctx context.Context, networkID string, payload any) error {
	if strings.TrimSpace(networkID) == "" {
		return fmt.Errorf("network ID is required")
	}
	return c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/networks/%s/cloudAccounts", networkID), payload, nil)
}

func (c *Client) AWSAssumeRoleExternalID(ctx context.Context, networkID string) (string, error) {
	if strings.TrimSpace(networkID) == "" {
		return "", fmt.Errorf("network ID is required")
	}
	var response ExternalIDResponse
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/networks/%s/cloudAccounts/aws/assumeRole/externalId", networkID), nil, &response); err != nil {
		return "", err
	}
	return strings.TrimSpace(response.ExternalID), nil
}

func (c *Client) AddWebhook(ctx context.Context, webhook Webhook) error {
	return c.doJSON(ctx, http.MethodPost, "/webhooks", webhook, nil)
}

func (c *Client) UpdateWebhook(ctx context.Context, name string, webhook Webhook) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("webhook name is required")
	}
	return c.doJSON(ctx, http.MethodPatch, fmt.Sprintf("/webhooks/%s", url.PathEscape(name)), webhook, nil)
}

func (c *Client) TestNewWebhook(ctx context.Context, webhook Webhook) (*WebhookTestResult, error) {
	var result WebhookTestResult
	if err := c.doJSON(ctx, http.MethodPost, "/webhooks?action=test", webhook, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpointPath string, requestBody any, out any) error {
	endpoint, err := c.resolve(endpointPath)
	if err != nil {
		return err
	}
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{
			Method:     method,
			Path:       endpoint.Path,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(respBody)),
		}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}

func (c *Client) resolve(endpointPath string) (*url.URL, error) {
	relative := endpointPath
	if !strings.HasPrefix(relative, "/") {
		relative = "/" + relative
	}
	if c.apiPrefix != "" && !strings.HasPrefix(relative, c.apiPrefix+"/") && relative != c.apiPrefix {
		relative = c.apiPrefix + relative
	}
	relativeURL, err := url.Parse(relative)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint path: %w", err)
	}
	return c.baseURL.ResolveReference(relativeURL), nil
}

func normalizeHost(host string) (*url.URL, error) {
	value := strings.TrimSpace(host)
	if value == "" {
		return nil, fmt.Errorf("host is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("host must include a scheme and hostname")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func normalizeAPIPrefix(prefix string) string {
	value := strings.TrimSpace(prefix)
	if value == "" || value == "/" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	value = path.Clean(value)
	if value == "." || value == "/" {
		return ""
	}
	return strings.TrimRight(value, "/")
}
