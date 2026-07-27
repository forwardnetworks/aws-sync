package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/app"
)

func TestAcceptedEventSurvivesCrashBeforeCompletion(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	event := durableTestEvent("evt-admitted")
	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})

	status, _ := handleDurableTestEvent(t, server, event)
	if status != http.StatusAccepted {
		t.Fatalf("admission status = %d; want %d", status, http.StatusAccepted)
	}
	state := mustLoadDurableTestState(t, statePath)
	job, exists := state.PendingEvents[eventDedupeKey(event)]
	if !exists {
		t.Fatal("accepted event is absent from durable pending state")
	}
	if job.Status != webhookJobQueued || job.Attempts != 0 {
		t.Fatalf("persisted job = %#v; want queued with zero attempts", job)
	}
	if _, completed := state.CompletedEvents[eventDedupeKey(event)]; completed {
		t.Fatal("accepted but incomplete event was recorded as completed")
	}

	// A real crash discards process-local admission signals and the channel.
	finishProcessAdmission(statePath, eventDedupeKey(event))
	if err := server.Close(); err != nil {
		t.Fatalf("release crashed daemon state lock: %v", err)
	}
	var recoveredRuns atomic.Int32
	restarted := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		recoveredRuns.Add(1)
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go restarted.worker(ctx)

	waitForDurableTestState(t, statePath, func(state webhookState) bool {
		_, pending := state.PendingEvents[eventDedupeKey(event)]
		_, completed := state.CompletedEvents[eventDedupeKey(event)]
		return !pending && completed
	})
	if got := recoveredRuns.Load(); got != 1 {
		t.Fatalf("recovered run count = %d; want 1", got)
	}
}

func TestInFlightEventIsReplayedAfterCrash(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	event := durableTestEvent("evt-in-flight")
	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	status, _ := handleDurableTestEvent(t, server, event)
	if status != http.StatusAccepted {
		t.Fatalf("admission status = %d; want %d", status, http.StatusAccepted)
	}
	queued := <-server.jobs
	if _, exists, err := server.markJobInFlight(queued); err != nil || !exists {
		t.Fatalf("markJobInFlight() exists=%v error=%v", exists, err)
	}
	finishProcessAdmission(statePath, eventDedupeKey(event))
	if err := server.Close(); err != nil {
		t.Fatalf("release crashed daemon state lock: %v", err)
	}

	restartedRuns := make(chan struct{}, 1)
	restarted := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		restartedRuns <- struct{}{}
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	state := mustLoadDurableTestState(t, statePath)
	if got := state.PendingEvents[eventDedupeKey(event)].Status; got != webhookJobQueued {
		t.Fatalf("recovered job status = %q; want %q", got, webhookJobQueued)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go restarted.worker(ctx)
	select {
	case <-restartedRuns:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight event was not replayed after restart")
	}
	waitForDurableTestState(t, statePath, func(state webhookState) bool {
		_, pending := state.PendingEvents[eventDedupeKey(event)]
		_, completed := state.CompletedEvents[eventDedupeKey(event)]
		return !pending && completed
	})
}

func TestFinalInFlightAttemptIsDeadLetteredAfterCrash(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	event := durableTestEvent("evt-final-crash")
	state := newWebhookState()
	now := time.Now().UTC()
	state.PendingEvents[eventDedupeKey(event)] = pendingWebhookEvent{
		Event:         event,
		Status:        webhookJobInFlight,
		Attempts:      webhookMaxAttempts,
		AcceptedAt:    now.Add(-time.Minute),
		LastAttemptAt: &now,
	}
	if err := persistWebhookState(statePath, state); err != nil {
		t.Fatalf("persist in-flight state: %v", err)
	}

	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		t.Fatal("final crashed attempt must remain visible for operator review instead of running forever")
		return nil, nil
	})
	if _, pending := server.state.PendingEvents[eventDedupeKey(event)]; pending {
		t.Fatal("exhausted in-flight event remains pending after restart")
	}
	deadLetter, exists := server.state.DeadLetterEvents[eventDedupeKey(event)]
	if !exists {
		t.Fatal("exhausted in-flight event was not dead-lettered after restart")
	}
	if deadLetter.Attempts != webhookMaxAttempts || !strings.Contains(deadLetter.LastError, "completion is ambiguous") {
		t.Fatalf("dead-letter record = %#v; want bounded ambiguous-crash record", deadLetter)
	}
}

func TestRetryExhaustionMovesEventToDeadLetterAndRedeliveryDrainsIt(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	event := durableTestEvent("evt-dead-letter")
	var (
		fail atomic.Bool
		runs atomic.Int32
	)
	fail.Store(true)
	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		runs.Add(1)
		if fail.Load() {
			return nil, errors.New("permanent test failure")
		}
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	server.maxAttempts = 3
	server.retryBaseDelay = time.Millisecond
	server.retryMaxDelay = 2 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.worker(ctx)

	status, _ := handleDurableTestEvent(t, server, event)
	if status != http.StatusAccepted {
		t.Fatalf("admission status = %d; want %d", status, http.StatusAccepted)
	}
	waitForDurableTestState(t, statePath, func(state webhookState) bool {
		_, deadLettered := state.DeadLetterEvents[eventDedupeKey(event)]
		return deadLettered
	})
	state := mustLoadDurableTestState(t, statePath)
	deadLetter := state.DeadLetterEvents[eventDedupeKey(event)]
	if deadLetter.Attempts != server.maxAttempts {
		t.Fatalf("dead-letter attempts = %d; want %d", deadLetter.Attempts, server.maxAttempts)
	}
	if _, pending := state.PendingEvents[eventDedupeKey(event)]; pending {
		t.Fatal("dead-lettered event remains pending")
	}
	if _, completed := state.CompletedEvents[eventDedupeKey(event)]; completed {
		t.Fatal("dead-lettered event was recorded as completed")
	}
	time.Sleep(10 * time.Millisecond)
	if got := runs.Load(); got != int32(server.maxAttempts) {
		t.Fatalf("run count after retry exhaustion = %d; want bounded count %d", got, server.maxAttempts)
	}

	// Re-delivering the original authenticated payload is the operator drain action.
	fail.Store(false)
	status, body := handleDurableTestEvent(t, server, event)
	if status != http.StatusAccepted {
		t.Fatalf("dead-letter redelivery status = %d; want %d", status, http.StatusAccepted)
	}
	if duplicate, _ := body["duplicate"].(bool); duplicate {
		t.Fatal("dead-letter redelivery reported duplicate instead of starting a fresh retry cycle")
	}
	waitForDurableTestState(t, statePath, func(state webhookState) bool {
		_, deadLettered := state.DeadLetterEvents[eventDedupeKey(event)]
		_, completed := state.CompletedEvents[eventDedupeKey(event)]
		return !deadLettered && completed
	})
}

func TestWebhookStateV1IsUpgraded(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	completedAt := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	mark := snapshotWatermark{
		NetworkID:   "network-1",
		SetupID:     "setup-1",
		SnapshotID:  "snapshot-1",
		SnapshotAt:  completedAt.Add(-time.Minute),
		CompletedAt: completedAt,
	}
	v1 := struct {
		Version         int                          `json:"version"`
		CompletedEvents map[string]time.Time         `json:"completed_events"`
		Watermarks      map[string]snapshotWatermark `json:"snapshot_watermarks"`
	}{
		Version:         previousWebhookStateVersion,
		CompletedEvents: map[string]time.Time{"completed-key": completedAt},
		Watermarks:      map[string]snapshotWatermark{watermarkKey("network-1", "setup-1"): mark},
	}
	data, err := json.Marshal(v1)
	if err != nil {
		t.Fatalf("marshal v1 state: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatalf("write v1 state: %v", err)
	}

	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	if server.state.Version != webhookStateVersion {
		t.Fatalf("loaded state version = %d; want %d", server.state.Version, webhookStateVersion)
	}
	upgraded := mustLoadDurableTestState(t, statePath)
	if upgraded.CompletedEvents["completed-key"] != completedAt {
		t.Fatal("v1 completed-event record was not preserved")
	}
	if got := upgraded.Watermarks[watermarkKey("network-1", "setup-1")]; got != mark {
		t.Fatalf("v1 watermark = %#v; want %#v", got, mark)
	}
	if upgraded.PendingEvents == nil || upgraded.DeadLetterEvents == nil {
		t.Fatal("v2 queue maps were not initialized")
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat upgraded state: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("upgraded state mode = %o; want 600", got)
	}
}

func TestAdmissionPersistenceFailureIsNotAcknowledged(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	server.persistState = func(string, webhookState) error {
		return errors.New("injected state write failure")
	}
	event := durableTestEvent("evt-persist-failure")

	status, body := handleDurableTestEvent(t, server, event)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("admission status = %d; want %d", status, http.StatusServiceUnavailable)
	}
	if message, _ := body["error"].(string); !strings.Contains(message, "persist accepted webhook event") {
		t.Fatalf("admission error = %q; want persistence failure", message)
	}
	if len(server.jobs) != 0 {
		t.Fatalf("queue depth = %d; want 0 after failed persistence", len(server.jobs))
	}
	if len(server.state.PendingEvents) != 0 {
		t.Fatal("failed admission remained pending in memory")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file exists after failed first admission; stat error=%v", err)
	}
}

func TestWorkerCompletionWaitsForDurableSuccess(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	event := durableTestEvent("evt-durable-completion")
	server := newDurableQueueServer(t, statePath, func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	})
	originalPersist := server.persistState
	durableWriteStarted := make(chan struct{})
	allowDurableWrite := make(chan struct{})
	var blocked atomic.Bool
	server.persistState = func(path string, state webhookState) error {
		if _, completed := state.CompletedEvents[eventDedupeKey(event)]; completed && blocked.CompareAndSwap(false, true) {
			close(durableWriteStarted)
			<-allowDurableWrite
		}
		return originalPersist(path, state)
	}
	defer func() {
		if blocked.Load() {
			select {
			case <-allowDurableWrite:
			default:
				close(allowDurableWrite)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go server.worker(ctx)
	status, _ := handleDurableTestEvent(t, server, event)
	if status != http.StatusAccepted {
		cancel()
		t.Fatalf("admission status = %d; want %d", status, http.StatusAccepted)
	}
	select {
	case <-durableWriteStarted:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("worker never reached durable success write")
	}
	cancel()
	select {
	case <-server.workerDone:
		t.Fatal("worker reported completion before successful state was durable")
	default:
	}
	close(allowDurableWrite)
	server.waitForWorker()

	state := mustLoadDurableTestState(t, statePath)
	if _, completed := state.CompletedEvents[eventDedupeKey(event)]; !completed {
		t.Fatal("worker completed without durable dedupe state")
	}
	if _, pending := state.PendingEvents[eventDedupeKey(event)]; pending {
		t.Fatal("worker completed with successfully processed event still pending")
	}
}

func TestRetryDelayIsExponentiallyBounded(t *testing.T) {
	server := &Server{retryBaseDelay: time.Second, retryMaxDelay: 5 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for index, expected := range want {
		if got := server.retryDelay(index + 1); got != expected {
			t.Errorf("retryDelay(%d) = %s; want %s", index+1, got, expected)
		}
	}
}

func newDurableQueueServer(t *testing.T, statePath string, run RunFunc) *Server {
	t.Helper()
	server, err := New(Config{
		StatePath: statePath,
		Logger:    log.New(io.Discard, "", 0),
		Run:       run,
		App: app.Config{
			Host:     "https://fwd.example",
			Username: "user",
			Password: "password",
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close webhook server: %v", err)
		}
	})
	return server
}

func durableTestEvent(id string) Event {
	return Event{
		ID:         id,
		Type:       "SNAPSHOT_READY",
		NetworkID:  "network-1",
		SnapshotID: "snapshot-1",
		SetupIDs:   []string{"setup-1"},
	}
}

func handleDurableTestEvent(t *testing.T, server *Server, event Event) (int, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, server.cfg.Path, bytes.NewReader(payload))
	response := httptest.NewRecorder()
	server.handleEvent(response, request)
	body := make(map[string]any)
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	return response.Code, body
}

func mustLoadDurableTestState(t *testing.T, statePath string) webhookState {
	t.Helper()
	state, err := loadWebhookState(statePath)
	if err != nil {
		t.Fatalf("load webhook state: %v", err)
	}
	return state
}

func waitForDurableTestState(t *testing.T, statePath string, ready func(webhookState) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		state := mustLoadDurableTestState(t, statePath)
		if ready(state) {
			return
		}
		if time.Now().After(deadline) {
			encoded, _ := json.Marshal(state)
			t.Fatalf("timed out waiting for webhook state transition: %s", encoded)
		}
		time.Sleep(time.Millisecond)
	}
}
