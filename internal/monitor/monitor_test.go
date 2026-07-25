package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestStatusReportsDisagreeingLatestAndListResponses(t *testing.T) {
	client, server := newTestClient(t, []string{
		`{"id":"latest","state":"PROCESSED"}`,
		`{"snapshots":[{"id":"other","state":"PROCESSED"}]}`,
	})
	defer server.Close()

	result, err := Status(context.Background(), client, "n1", "")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if result.ObservationAtomic {
		t.Fatal("Status() reported an atomic observation from separate API requests")
	}
	if result.LatestListConsistent {
		t.Fatal("Status() reported disagreeing latest/list responses as consistent")
	}
	if !strings.Contains(result.ObservationWarning, "latest") || !strings.Contains(result.ObservationWarning, "absent") {
		t.Fatalf("unexpected observation warning: %q", result.ObservationWarning)
	}
}

func TestStatusFindsSnapshotBeyondFirstPage(t *testing.T) {
	firstPage := make([]api.SnapshotInfo, api.PageLimit)
	for index := range firstPage {
		firstPage[index] = api.SnapshotInfo{ID: fmt.Sprintf("snapshot-%04d", index), State: "PROCESSED"}
	}
	firstPageJSON := mustSnapshotsJSON(t, firstPage)
	secondPageJSON := mustSnapshotsJSON(t, []api.SnapshotInfo{{ID: "target", State: "PROCESSED"}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/networks/n1/snapshots/latestProcessed":
			_, _ = w.Write([]byte(`{"id":"target","state":"PROCESSED"}`))
		case "/api/networks/n1/snapshots":
			if r.URL.Query().Get("includeArchived") != "true" || r.URL.Query().Get("limit") != fmt.Sprint(api.PageLimit) {
				t.Errorf("unexpected snapshot query: %s", r.URL.RawQuery)
			}
			switch r.URL.Query().Get("offset") {
			case "0":
				_, _ = w.Write([]byte(firstPageJSON))
			case fmt.Sprint(api.PageLimit):
				_, _ = w.Write([]byte(secondPageJSON))
			default:
				t.Errorf("unexpected snapshot offset: %s", r.URL.Query().Get("offset"))
				http.Error(w, "unexpected offset", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := api.NewClient(server.URL, "/api", "u", "p", false, time.Second)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := Status(context.Background(), client, "n1", "target")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if len(result.Snapshots) != 1 || result.Snapshots[0].ID != "target" {
		t.Fatalf("unexpected snapshots: %#v", result.Snapshots)
	}
	if !result.LatestListConsistent {
		t.Fatalf("expected paginated list to contain latest snapshot: %#v", result)
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

func TestWaitRejectsUnknownState(t *testing.T) {
	client, server := newTestClient(t, []string{
		`{"snapshots":[{"id":"s1","state":"SOMETHING_NEW"}]}`,
	})
	defer server.Close()

	_, err := Wait(context.Background(), client, "n1", "s1", "PROCESSED", time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), `unrecognized state "SOMETHING_NEW"`) {
		t.Fatalf("Wait() error = %v; want unrecognized-state error", err)
	}
}

func TestWaitRejectsUnknownDesiredState(t *testing.T) {
	client, server := newTestClient(t, nil)
	defer server.Close()

	_, err := Wait(context.Background(), client, "n1", "s1", "SOMETHING_NEW", time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), `desired snapshot state "SOMETHING_NEW" is unrecognized`) {
		t.Fatalf("Wait() error = %v; want unrecognized desired-state error", err)
	}
}

func TestWaitRecognizesMixedCaseTerminalStates(t *testing.T) {
	for _, state := range []string{"failed", "ArChIvEd"} {
		t.Run(state, func(t *testing.T) {
			client, server := newTestClient(t, []string{
				fmt.Sprintf(`{"snapshots":[{"id":"s1","state":%q}]}`, state),
			})
			defer server.Close()

			_, err := Wait(context.Background(), client, "n1", "s1", "processed", time.Millisecond)
			if err == nil || !strings.Contains(err.Error(), "terminal state "+state) {
				t.Fatalf("Wait() error = %v; want terminal-state error", err)
			}
		})
	}
}

func TestWaitFailsFastWhenSnapshotIsMissing(t *testing.T) {
	client, server := newTestClient(t, []string{
		`{"snapshots":[{"id":"other","state":"PROCESSING"}]}`,
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Wait(ctx, client, "n1", "missing", "PROCESSED", 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "snapshot missing not found in network n1") {
		t.Fatalf("Wait() error = %v; want missing-snapshot error", err)
	}
}

func mustSnapshotsJSON(t *testing.T, snapshots []api.SnapshotInfo) string {
	t.Helper()
	encoded, err := json.Marshal(api.NetworkSnapshots{Snapshots: snapshots})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
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
