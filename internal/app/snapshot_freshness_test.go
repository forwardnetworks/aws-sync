package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestValidateSnapshotFreshnessChecksExplicitSnapshot(t *testing.T) {
	staleAt := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/network-1/snapshots" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"snapshots":[{"id":"snapshot-stale","processedAt":"`+staleAt+`","state":"PROCESSED"}]}`)
	}))
	defer server.Close()

	client, err := api.NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	err = validateSnapshotFreshness(context.Background(), client, Config{
		NetworkID:      "network-1",
		SnapshotID:     "snapshot-stale",
		MaxSnapshotAge: time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "explicit snapshot snapshot-stale is stale") {
		t.Fatalf("validateSnapshotFreshness() error = %v; want explicit stale-snapshot rejection", err)
	}
}

func TestValidateSnapshotFreshnessAcceptsFreshExplicitSnapshot(t *testing.T) {
	freshAt := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/network-1/snapshots" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"snapshots":[{"id":"snapshot-fresh","processedAt":"`+freshAt+`","state":"PROCESSED"}]}`)
	}))
	defer server.Close()

	client, err := api.NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := validateSnapshotFreshness(context.Background(), client, Config{
		NetworkID:      "network-1",
		SnapshotID:     "snapshot-fresh",
		MaxSnapshotAge: time.Hour,
	}); err != nil {
		t.Fatalf("validateSnapshotFreshness() error = %v", err)
	}
}
