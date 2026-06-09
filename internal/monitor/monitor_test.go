package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestStatusFiltersBySnapshotID(t *testing.T) {
	client, server := newTestClient(t, []string{
		`{"id":"old","state":"PROCESSED","processedAt":"2026-03-25T10:00:00Z"}`,
		`{"snapshots":[{"id":"new","state":"PROCESSING"},{"id":"old","state":"PROCESSED"}]}`,
	})
	defer server.Close()

	result, err := Status(context.Background(), client, "n1", "new")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if len(result.Snapshots) != 1 || result.Snapshots[0].ID != "new" {
		t.Fatalf("unexpected snapshots: %#v", result.Snapshots)
	}
	if result.LatestProcessedSnapshot == nil || result.LatestProcessedSnapshot.ID != "old" {
		t.Fatalf("unexpected latest processed snapshot: %#v", result.LatestProcessedSnapshot)
	}
}

func TestWaitReturnsWhenDesiredStateReached(t *testing.T) {
	client, server := newTestClient(t, []string{
		`{"snapshots":[{"id":"s1","state":"PROCESSING"}]}`,
		`{"snapshots":[{"id":"s1","state":"PROCESSED","processedAt":"2026-03-25T10:05:00Z"}]}`,
		`{"id":"s1","state":"PROCESSED","processedAt":"2026-03-25T10:05:00Z"}`,
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := Wait(ctx, client, "n1", "s1", "PROCESSED", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if result.Snapshot.ID != "s1" || result.Snapshot.State != "PROCESSED" {
		t.Fatalf("unexpected wait result: %#v", result)
	}
}

func newTestClient(t *testing.T, responses []string) (*api.Client, *httptest.Server) {
	t.Helper()
	index := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if index >= len(responses) {
			t.Fatalf("unexpected extra request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responses[index]))
		index++
	}))
	client, err := api.NewClient(server.URL, "/api", "u", "p", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client, server
}
