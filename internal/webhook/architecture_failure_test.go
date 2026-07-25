package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/app"
)

const runP0WebhookFailureTests = false

func skipUntilP0WebhookFixed(t *testing.T, finding string) {
	t.Helper()
	if !runP0WebhookFailureTests {
		t.Skip("P0 characterization disabled until fixed: " + finding)
	}
}

func TestP0WebhookDeliveryAndScopeSafety(t *testing.T) {
	skipUntilP0WebhookFixed(t, "webhook dedupe/order/scope are not durable or monotonic — docs/ARCHITECTURE_REVIEW.md §4, Ordering, time, and monitor/webhook behavior; §5, Bypasses")

	t.Run("queue full does not poison dedupe", func(t *testing.T) {
		server := newP0WebhookServer(t, Config{})
		for i := 0; i < cap(server.jobs); i++ {
			server.jobs <- Event{ID: fmt.Sprintf("filler-%d", i)}
		}
		event := Event{
			ID:         "evt-queue-full",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: "snapshot-1",
		}
		firstStatus, _ := p0HandleWebhookEvent(t, server, event)
		if firstStatus != http.StatusServiceUnavailable {
			t.Fatalf("first status = %d; want %d for full queue", firstStatus, http.StatusServiceUnavailable)
		}
		<-server.jobs

		secondStatus, secondBody := p0HandleWebhookEvent(t, server, event)
		if secondStatus != http.StatusAccepted {
			t.Errorf("retry status = %d; want %d after queue space becomes available", secondStatus, http.StatusAccepted)
		}
		if duplicate, _ := secondBody["duplicate"].(bool); duplicate {
			t.Errorf("retry body duplicate = true; want false because the first delivery was never admitted")
		}
		if depth := len(server.jobs); depth != cap(server.jobs) {
			t.Errorf("queue depth after retry = %d; want %d so the previously rejected event is not lost", depth, cap(server.jobs))
		}
	})

	t.Run("failed run is redeliverable", func(t *testing.T) {
		var attempts atomic.Int32
		attemptCh := make(chan int, 2)
		server := newP0WebhookServer(t, Config{
			Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
				attempt := int(attempts.Add(1))
				attemptCh <- attempt
				if attempt == 1 {
					return nil, errors.New("injected reconciliation failure")
				}
				return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go server.worker(ctx)

		event := Event{
			ID:         "evt-redelivery",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: "snapshot-1",
		}
		firstStatus, _ := p0HandleWebhookEvent(t, server, event)
		if firstStatus != http.StatusAccepted {
			t.Fatalf("first status = %d; want %d", firstStatus, http.StatusAccepted)
		}
		p0WaitForAttempt(t, attemptCh, 1)

		secondStatus, _ := p0HandleWebhookEvent(t, server, event)
		if secondStatus != http.StatusAccepted {
			t.Errorf("redelivery status = %d; want %d", secondStatus, http.StatusAccepted)
		}
		select {
		case attempt := <-attemptCh:
			if attempt != 2 {
				t.Errorf("redelivery attempt = %d; want 2", attempt)
			}
		case <-time.After(250 * time.Millisecond):
			t.Errorf("redelivery was silently suppressed after failed run; attempts=%d want=2", attempts.Load())
		}
	})

	t.Run("restart retains successful dedupe", func(t *testing.T) {
		var attempts atomic.Int32
		attemptCh := make(chan int, 2)
		statePath := filepath.Join(t.TempDir(), "webhook-state.json")
		cfg := Config{
			StatePath: statePath,
			Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
				attempt := int(attempts.Add(1))
				attemptCh <- attempt
				return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
			},
		}
		event := Event{
			ID:         "evt-persisted",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: "snapshot-1",
		}

		first := newP0WebhookServer(t, cfg)
		firstCtx, firstCancel := context.WithCancel(context.Background())
		go first.worker(firstCtx)
		firstStatus, _ := p0HandleWebhookEvent(t, first, event)
		if firstStatus != http.StatusAccepted {
			firstCancel()
			t.Fatalf("first status = %d; want %d", firstStatus, http.StatusAccepted)
		}
		p0WaitForAttempt(t, attemptCh, 1)
		firstCancel()

		restarted := newP0WebhookServer(t, cfg)
		secondCtx, secondCancel := context.WithCancel(context.Background())
		defer secondCancel()
		go restarted.worker(secondCtx)
		secondStatus, secondBody := p0HandleWebhookEvent(t, restarted, event)
		if secondStatus != http.StatusAccepted {
			t.Errorf("post-restart duplicate status = %d; want %d", secondStatus, http.StatusAccepted)
		}
		if duplicate, _ := secondBody["duplicate"].(bool); !duplicate {
			t.Errorf("post-restart duplicate = false; want durable duplicate recognition")
		}
		select {
		case attempt := <-attemptCh:
			t.Errorf("post-restart duplicate executed as attempt %d; want total attempts=1", attempt)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("event ID collision does not suppress different scope", func(t *testing.T) {
		server := newP0WebhookServer(t, Config{})
		first := Event{
			ID:         "shared-event-id",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: "snapshot-1",
		}
		second := Event{
			ID:         "shared-event-id",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-2",
			SnapshotID: "snapshot-2",
		}
		firstStatus, _ := p0HandleWebhookEvent(t, server, first)
		if firstStatus != http.StatusAccepted {
			t.Fatalf("first status = %d; want %d", firstStatus, http.StatusAccepted)
		}
		secondStatus, secondBody := p0HandleWebhookEvent(t, server, second)
		if secondStatus != http.StatusAccepted {
			t.Errorf("second status = %d; want %d", secondStatus, http.StatusAccepted)
		}
		if duplicate, _ := secondBody["duplicate"].(bool); duplicate {
			t.Errorf("second event duplicate = true; want false when network/snapshot scope differs")
		}
		if depth := len(server.jobs); depth != 2 {
			t.Errorf("queue depth = %d; want 2 distinct scoped events", depth)
		}
	})

	t.Run("older snapshot cannot follow newer snapshot", func(t *testing.T) {
		const (
			newerSnapshotID = "snapshot-new"
			olderSnapshotID = "snapshot-old"
		)
		forward := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/networks/network-1/snapshots":
				_, _ = io.WriteString(w, `{"snapshots":[
					{"id":"snapshot-new","createdAt":"2026-07-25T12:00:00Z","processedAt":"2026-07-25T12:05:00Z","state":"PROCESSED"},
					{"id":"snapshot-old","createdAt":"2026-07-25T11:00:00Z","processedAt":"2026-07-25T11:05:00Z","state":"PROCESSED"}
				]}`)
			case "/api/networks/network-1/snapshots/latestProcessed":
				_, _ = io.WriteString(w, `{"id":"snapshot-new","createdAt":"2026-07-25T12:00:00Z","processedAt":"2026-07-25T12:05:00Z","state":"PROCESSED"}`)
			default:
				http.NotFound(w, r)
			}
		}))
		defer forward.Close()

		var (
			mu    sync.Mutex
			calls []string
		)
		callCh := make(chan string, 2)
		server := newP0WebhookServer(t, Config{
			App: app.Config{
				Host:      forward.URL,
				Username:  "alice",
				Password:  "secret",
				NetworkID: "network-1",
				APIPrefix: "/api",
			},
			Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
				mu.Lock()
				calls = append(calls, cfg.SnapshotID)
				mu.Unlock()
				callCh <- cfg.SnapshotID
				return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go server.worker(ctx)

		newer := Event{
			ID:         "evt-newer",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: newerSnapshotID,
		}
		older := Event{
			ID:         "evt-older",
			Type:       "SNAPSHOT_READY",
			NetworkID:  "network-1",
			SnapshotID: olderSnapshotID,
		}
		newerStatus, _ := p0HandleWebhookEvent(t, server, newer)
		if newerStatus != http.StatusAccepted {
			t.Fatalf("newer status = %d; want %d", newerStatus, http.StatusAccepted)
		}
		p0WaitForSnapshot(t, callCh, newer.SnapshotID)

		olderStatus, _ := p0HandleWebhookEvent(t, server, older)
		if olderStatus == http.StatusAccepted {
			t.Errorf("older snapshot status = %d; want rejection after newer snapshot completed", olderStatus)
		}
		select {
		case snapshotID := <-callCh:
			t.Errorf("older snapshot %s executed after newer snapshot; want monotonic per-network watermark", snapshotID)
		case <-time.After(100 * time.Millisecond):
		}
		mu.Lock()
		gotCalls := append([]string(nil), calls...)
		mu.Unlock()
		if len(gotCalls) != 1 || gotCalls[0] != newer.SnapshotID {
			t.Errorf("snapshot calls = %v; want [%s]", gotCalls, newer.SnapshotID)
		}
	})

	t.Run("event cannot expand configured scope", func(t *testing.T) {
		tests := []struct {
			name  string
			event Event
		}{
			{
				name: "network",
				event: Event{
					ID:         "evt-network-expansion",
					Type:       "SNAPSHOT_READY",
					NetworkID:  "other-network",
					SnapshotID: "snapshot-1",
					SetupIDs:   []string{"allowed-setup"},
				},
			},
			{
				name: "setup",
				event: Event{
					ID:         "evt-setup-expansion",
					Type:       "SNAPSHOT_READY",
					NetworkID:  "allowed-network",
					SnapshotID: "snapshot-1",
					SetupIDs:   []string{"other-setup"},
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				server := newP0WebhookServer(t, Config{
					App: app.Config{
						Host:      "https://fwd.example",
						Username:  "alice",
						Password:  "secret",
						NetworkID: "allowed-network",
						SetupIDs:  []string{"allowed-setup"},
					},
				})
				status, _ := p0HandleWebhookEvent(t, server, test.event)
				if status >= 200 && status < 300 {
					t.Errorf("scope-expansion status = %d; want non-2xx rejection for configured scope", status)
				}
				if depth := len(server.jobs); depth != 0 {
					t.Errorf("queue depth = %d; want 0 after scope-expansion attempt", depth)
				}
			})
		}
	})
}

func newP0WebhookServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.App.Host == "" {
		cfg.App = app.Config{
			Host:     "https://fwd.example",
			Username: "alice",
			Password: "secret",
		}
	}
	if cfg.StatePath == "" {
		cfg.StatePath = filepath.Join(t.TempDir(), "webhook-state.json")
	}
	cfg.Logger = log.New(io.Discard, "", 0)
	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		waitForWebhookStateIdle(t, server)
	})
	return server
}

func p0HandleWebhookEvent(t *testing.T, server *Server, event Event) (int, map[string]any) {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, server.cfg.Path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handleEvent(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	body := make(map[string]any)
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body
}

func p0WaitForAttempt(t *testing.T, attempts <-chan int, want int) {
	t.Helper()
	select {
	case got := <-attempts:
		if got != want {
			t.Fatalf("run attempt = %d; want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for run attempt %d", want)
	}
}

func p0WaitForSnapshot(t *testing.T, snapshots <-chan string, want string) {
	t.Helper()
	select {
	case got := <-snapshots:
		if got != want {
			t.Fatalf("snapshot run = %q; want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for snapshot %q", want)
	}
}
