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

func TestValidateSnapshotFreshnessRejectsFutureExplicitSnapshot(t *testing.T) {
	futureAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/networks/network-1/snapshots" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"snapshots":[{"id":"snapshot-future","processedAt":"`+futureAt+`","state":"PROCESSED"}]}`)
	}))
	defer server.Close()

	client, err := api.NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	err = validateSnapshotFreshness(context.Background(), client, Config{
		NetworkID:      "network-1",
		SnapshotID:     "snapshot-future",
		MaxSnapshotAge: time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid future timestamp") {
		t.Fatalf("validateSnapshotFreshness() error = %v; want future-timestamp rejection", err)
	}
}

func TestPinLatestProcessedSnapshotRejectsFutureSnapshot(t *testing.T) {
	futureAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"snapshot-future","processedAt":"`+futureAt+`","state":"PROCESSED"}`)
	}))
	defer server.Close()

	client, err := api.NewClient(server.URL, "/api", "alice", "secret", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	cfg := Config{NetworkID: "network-1", MaxSnapshotAge: time.Hour}
	if err := pinLatestProcessedSnapshot(context.Background(), client, &cfg); err == nil || !strings.Contains(err.Error(), "invalid future timestamp") {
		t.Fatalf("pinLatestProcessedSnapshot() error = %v; want future-timestamp rejection", err)
	}
}

func TestValidateSnapshotFreshnessToleratesSmallClockSkew(t *testing.T) {
	skewedAt := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339)
	if _, err := checkedSnapshotAge(api.SnapshotInfo{ID: "snapshot-skewed", ProcessedAt: skewedAt}, "explicit"); err != nil {
		t.Fatalf("checkedSnapshotAge() rejected ordinary clock skew: %v", err)
	}
	aheadAt := time.Now().UTC().Add(snapshotClockSkewTolerance + time.Minute).Format(time.RFC3339)
	if _, err := checkedSnapshotAge(api.SnapshotInfo{ID: "snapshot-future", ProcessedAt: aheadAt}, "explicit"); err == nil {
		t.Fatal("checkedSnapshotAge() accepted a timestamp beyond the skew tolerance")
	}
}
