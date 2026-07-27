package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/app"
)

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("unexpected healthz body: %#v", body)
	}
}

func TestHandleEventRequiresBasicAuth(t *testing.T) {
	ts, _ := newTestServer(t, Config{BasicUsername: "hook", BasicPassword: "secret"})
	defer ts.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		ts.URL+"/forward/snapshot-ready",
		strings.NewReader(`{"networkId":"n1","snapshotId":"s1"}`),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
}

func TestNewRequiresBasicAuthWhenApplyEnabled(t *testing.T) {
	_, err := New(Config{
		StatePath: filepath.Join(t.TempDir(), "webhook-state.json"),
		App: app.Config{
			Host:     "https://fwd.example",
			Username: "alice",
			Password: "secret",
			Apply:    true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "Basic authentication") {
		t.Fatalf("New() error = %v; want apply-mode Basic Auth requirement", err)
	}
}

func TestNewRequiresConfiguredNetworkWhenApplyEnabled(t *testing.T) {
	_, err := New(Config{
		BasicUsername: "hook",
		BasicPassword: "secret",
		StatePath:     filepath.Join(t.TempDir(), "webhook-state.json"),
		App: app.Config{
			Host:     "https://fwd.example",
			Username: "alice",
			Password: "secret",
			Apply:    true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "network ID is required") {
		t.Fatalf("New() error = %v; want apply-mode configured-network requirement", err)
	}
}

func TestNewRefusesSecondDaemonForSameStateFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "webhook-state.json")
	cfg := Config{
		StatePath: statePath,
		Logger:    log.New(io.Discard, "", 0),
		Run: func(context.Context, app.Config) (*app.Summary, error) {
			return &app.Summary{}, nil
		},
		App: app.Config{
			Host:     "https://fwd.example",
			Username: "alice",
			Password: "secret",
		},
	}
	first, err := New(cfg)
	if err != nil {
		t.Fatalf("first New() error = %v", err)
	}
	defer first.Close()

	second, err := New(cfg)
	if second != nil || err == nil || !strings.Contains(err.Error(),
		"webhook state file "+statePath+" is already locked by another process; only one webhook daemon may use a state file") {
		t.Fatalf("second New() server=%v error=%v; want state-file lock refusal", second, err)
	}
}

func TestHandleEventQueuesExactSnapshot(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []app.Config
		runCh = make(chan struct{}, 2)
	)
	ts, _ := newTestServer(t, Config{Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
		mu.Lock()
		calls = append(calls, cfg)
		mu.Unlock()
		runCh <- struct{}{}
		return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
	}})
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/forward/snapshot-ready", strings.NewReader(`{"id":"evt-1","type":"SNAPSHOT_READY","networkId":"n1","snapshotId":"s1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	select {
	case <-runCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run call")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("unexpected calls: %#v", calls)
	}
	if calls[0].NetworkID != "n1" || calls[0].SnapshotID != "s1" {
		t.Fatalf("unexpected run config: %#v", calls[0])
	}
}

func TestHandleEventScopesSetupIDsFromQuery(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []app.Config
		runCh = make(chan struct{}, 1)
	)
	ts, _ := newTestServer(t, Config{
		Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
			mu.Lock()
			calls = append(calls, cfg)
			mu.Unlock()
			runCh <- struct{}{}
			return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID, SetupIDs: cfg.SetupIDs}, nil
		},
	})
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/forward/snapshot-ready?setupId=setup-b&setupId=setup-a", strings.NewReader(`{"id":"evt-setup","type":"SNAPSHOT_READY","networkId":"n1","snapshotId":"s1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	select {
	case <-runCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run call")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("unexpected calls: %#v", calls)
	}
	if strings.Join(calls[0].SetupIDs, ",") != "setup-a,setup-b" {
		t.Fatalf("unexpected setup IDs: %#v", calls[0].SetupIDs)
	}
}

func TestHandleEventAcceptsBasicAuth(t *testing.T) {
	runCh := make(chan struct{}, 1)
	ts, _ := newTestServer(t, Config{
		BasicUsername: "hook",
		BasicPassword: "secret",
		Run: func(_ context.Context, cfg app.Config) (*app.Summary, error) {
			runCh <- struct{}{}
			return &app.Summary{NetworkID: cfg.NetworkID, SnapshotID: cfg.SnapshotID}, nil
		},
	})
	defer ts.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		ts.URL+"/forward/snapshot-ready",
		strings.NewReader(`{"id":"evt-1","type":"SNAPSHOT_READY","networkId":"n1","snapshotId":"s1"}`),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.SetBasicAuth("hook", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	select {
	case <-runCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run call")
	}
}

func newTestServer(t *testing.T, cfg Config) (*httptest.Server, *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg.Listen = "127.0.0.1:0"
	cfg.Path = "/forward/snapshot-ready"
	cfg.StatePath = filepath.Join(t.TempDir(), "webhook-state.json")
	cfg.Logger = log.New(io.Discard, "", 0)
	cfg.App = app.Config{Host: "https://fwd.example", Username: "u", Password: "p"}
	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close webhook server: %v", err)
		}
	})
	t.Cleanup(func() {
		waitForWebhookStateIdle(t, server)
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", server.handleHealthz)
	mux.HandleFunc(server.cfg.Path, server.handleEvent)
	go server.worker(ctx)
	return httptest.NewServer(mux), server
}

func waitForWebhookStateIdle(t *testing.T, server *Server) {
	t.Helper()
	if !server.workerRunning.Load() {
		processAdmissions.Lock()
		for _, done := range processAdmissions.byStatePath[server.cfg.StatePath] {
			close(done)
		}
		delete(processAdmissions.byStatePath, server.cfg.StatePath)
		processAdmissions.Unlock()
		return
	}
	deadline := time.Now().Add(time.Second)
	for {
		processAdmissions.Lock()
		pending := len(processAdmissions.byStatePath[server.cfg.StatePath])
		processAdmissions.Unlock()
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("timed out waiting for webhook state writes to finish")
			return
		}
		time.Sleep(time.Millisecond)
	}
}
