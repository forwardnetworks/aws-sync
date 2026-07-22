package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryAWSAccountsPagesResults(t *testing.T) {
	var seenOffsets []int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/nqe" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		seenOffsets = append(seenOffsets, req.QueryOptions.Offset)
		if req.QueryID != "query-1" {
			t.Fatalf("unexpected query id %q", req.QueryID)
		}
		if len(req.QueryOptions.ColumnFilters) != 1 || req.QueryOptions.ColumnFilters[0].ColumnName != "Cloud Type" || req.QueryOptions.ColumnFilters[0].Value != "AWS" {
			t.Fatalf("unexpected filters: %#v", req.QueryOptions.ColumnFilters)
		}
		w.Header().Set("Content-Type", "application/json")
		if req.QueryOptions.Offset == 0 {
			items := make([]map[string]any, PageLimit)
			for i := range items {
				items[i] = map[string]any{"Cloud Account ID": "a"}
			}
			_ = json.NewEncoder(w).Encode(NQEResponse{Items: items})
			return
		}
		_ = json.NewEncoder(w).Encode(NQEResponse{Items: []map[string]any{{"Cloud Account ID": "b"}}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	items, err := client.QueryAWSAccounts(context.Background(), "network-1", "", "", "query-1", nil, nil)
	if err != nil {
		t.Fatalf("QueryAWSAccounts() error = %v", err)
	}
	if len(items) != PageLimit+1 {
		t.Fatalf("expected %d items, got %d", PageLimit+1, len(items))
	}
	if len(seenOffsets) != 2 || seenOffsets[0] != 0 || seenOffsets[1] != PageLimit {
		t.Fatalf("unexpected offsets: %#v", seenOffsets)
	}
}

func TestQueryAWSAccountsAddsSnapshotIDQueryParam(t *testing.T) {
	var rawQuery string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NQEResponse{Items: []map[string]any{{"Cloud Account ID": "a"}}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.QueryAWSAccounts(context.Background(), "network-1", "snapshot-1", "", "query-1", nil, nil)
	if err != nil {
		t.Fatalf("QueryAWSAccounts() error = %v", err)
	}
	if rawQuery != "networkId=network-1&snapshotId=snapshot-1" && rawQuery != "snapshotId=snapshot-1&networkId=network-1" {
		t.Fatalf("unexpected raw query %q", rawQuery)
	}
}

func TestQueryAWSAccountsUsesSourceQueryAndSingleSetupFilter(t *testing.T) {
	var req QueryRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NQEResponse{Items: []map[string]any{{"Cloud Account ID": "a"}}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.QueryAWSAccounts(context.Background(), "network-1", "", "foreach x in y select x", "", map[string]any{"setupId": "setup-a"}, []string{"setup-a"})
	if err != nil {
		t.Fatalf("QueryAWSAccounts() error = %v", err)
	}
	if req.Query != "foreach x in y select x" || req.QueryID != "" {
		t.Fatalf("unexpected query fields: %#v", req)
	}
	if req.Parameters["setupId"] != "setup-a" {
		t.Fatalf("unexpected query parameters: %#v", req.Parameters)
	}
	if len(req.QueryOptions.ColumnFilters) != 2 {
		t.Fatalf("unexpected filters: %#v", req.QueryOptions.ColumnFilters)
	}
	if req.QueryOptions.ColumnFilters[1].ColumnName != "Cloud Setup ID" ||
		req.QueryOptions.ColumnFilters[1].Value != "setup-a" {
		t.Fatalf("missing setup filter: %#v", req.QueryOptions.ColumnFilters)
	}
}

func TestQueryAWSAccountsFiltersMultipleSetupsLocally(t *testing.T) {
	var req QueryRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NQEResponse{Items: []map[string]any{
			{"Cloud Setup ID": "setup-a", "Cloud Account ID": "a"},
			{"Cloud Setup ID": "setup-b", "Cloud Account ID": "b"},
			{"Cloud Setup ID": "setup-c", "Cloud Account ID": "c"},
		}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	items, err := client.QueryAWSAccounts(context.Background(), "network-1", "", "", "query-1", nil, []string{"setup-b", "setup-a"})
	if err != nil {
		t.Fatalf("QueryAWSAccounts() error = %v", err)
	}
	if len(req.QueryOptions.ColumnFilters) != 1 {
		t.Fatalf("unexpected server-side filters: %#v", req.QueryOptions.ColumnFilters)
	}
	if len(items) != 2 {
		t.Fatalf("expected two locally filtered items, got %#v", items)
	}
}

func TestAddWebhookPostsSnapshotReadyPayload(t *testing.T) {
	var req Webhook
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/webhooks" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	err = client.AddWebhook(context.Background(), Webhook{
		Name: "awssync",
		URL:  "https://awssync.example.com/forward/snapshot-ready",
		EventParams: WebhookEventParams{
			Type:       "SNAPSHOT_READY",
			NetworkIDs: []string{"network-1"},
		},
		Credential: &WebhookBasicAuth{Type: "BASIC_AUTH", Username: "hook", Password: "secret"},
		Enabled:    true,
		Template:   WebhookTemplate{PayloadFormat: "JSON", Template: `{"networkId":"$networkId"}`},
	})
	if err != nil {
		t.Fatalf("AddWebhook() error = %v", err)
	}
	if req.EventParams.Type != "SNAPSHOT_READY" || len(req.EventParams.NetworkIDs) != 1 {
		t.Fatalf("unexpected event params: %#v", req.EventParams)
	}
	if req.Credential == nil || req.Credential.Type != "BASIC_AUTH" || req.Credential.Username != "hook" {
		t.Fatalf("unexpected credential: %#v", req.Credential)
	}
}

func TestUpdateWebhookPatchesNamedWebhook(t *testing.T) {
	var req Webhook
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/webhooks/awssync" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	err = client.UpdateWebhook(context.Background(), "awssync", Webhook{
		Name:        "awssync",
		URL:         "https://awssync.example.com/forward/snapshot-ready?setupId=setup-a",
		EventParams: WebhookEventParams{Type: "SNAPSHOT_READY", NetworkIDs: []string{"network-1"}},
		Enabled:     true,
		Template:    WebhookTemplate{PayloadFormat: "JSON", Template: `{"snapshotId":"$snapshotId"}`},
	})
	if err != nil {
		t.Fatalf("UpdateWebhook() error = %v", err)
	}
	if req.URL != "https://awssync.example.com/forward/snapshot-ready?setupId=setup-a" {
		t.Fatalf("unexpected patched URL: %#v", req)
	}
}

func TestDuplicateWebhookErrorDetection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`duplicate webhook name`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	err = client.AddWebhook(context.Background(), Webhook{
		Name:        "awssync",
		URL:         "https://awssync.example.com/forward/snapshot-ready",
		EventParams: WebhookEventParams{Type: "SNAPSHOT_READY", NetworkIDs: []string{"network-1"}},
		Enabled:     true,
		Template:    WebhookTemplate{PayloadFormat: "JSON", Template: `{"snapshotId":"$snapshotId"}`},
	})
	if !IsDuplicateWebhookError(err) {
		t.Fatalf("expected duplicate webhook error, got %v", err)
	}
}

func TestIdempotentRequestsRetryTransientFailures(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{
			name: "get",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Networks(ctx)
				return err
			},
		},
		{
			name: "patch",
			call: func(ctx context.Context, client *Client) error {
				return client.PatchCloudAccount(ctx, "network-1", "setup-1", map[string]any{"name": "setup-1"})
			},
		},
		{
			name: "nqe read post",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryAWSAccounts(ctx, "network-1", "snapshot-1", "", "query-1", nil, nil)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				if attempts < 3 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/networks":
					_, _ = w.Write([]byte(`[]`))
				case "/api/nqe":
					_, _ = w.Write([]byte(`{"items":[]}`))
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			client.retryDelay = time.Millisecond
			if err := tt.call(context.Background(), client); err != nil {
				t.Fatalf("request error = %v", err)
			}
			if attempts != 3 {
				t.Fatalf("expected 3 attempts, got %d", attempts)
			}
		})
	}
}

func TestCreateCloudAccountDoesNotRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.retryDelay = time.Millisecond
	err = client.CreateCloudAccount(context.Background(), "network-1", map[string]any{"name": "setup-1"})
	if !IsHTTPStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("expected 503 error, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
}

func TestRetryWaitHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		cancel()
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "/api", "alice", "secret", true, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = client.Networks(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRetryDelayIsBounded(t *testing.T) {
	if got := retryDelay(time.Second, 10, ""); got != maxRetryDelay {
		t.Fatalf("exponential delay = %s; want %s", got, maxRetryDelay)
	}
	if got := retryDelay(time.Second, 1, "600"); got != maxRetryDelay {
		t.Fatalf("Retry-After delay = %s; want %s", got, maxRetryDelay)
	}
}
