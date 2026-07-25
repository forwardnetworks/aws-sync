package webhook

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
	"github.com/forwardnetworks/aws-sync/internal/app"
)

type RunFunc func(context.Context, app.Config) (*app.Summary, error)

type Config struct {
	Listen        string
	Path          string
	BasicUsername string
	BasicPassword string
	StatePath     string
	App           app.Config
	Logger        *log.Logger
	Run           RunFunc
}

type Event struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	NetworkID  string   `json:"networkId"`
	SnapshotID string   `json:"snapshotId"`
	SetupIDs   []string `json:"setupIds,omitempty"`
}

type Server struct {
	cfg    Config
	logger *log.Logger
	run    RunFunc
	jobs   chan Event

	stateMu            sync.Mutex
	state              webhookState
	active             map[string]snapshotWatermark
	lookupSnapshotTime bool
	workerRunning      atomic.Bool
}

func New(cfg Config) (*Server, error) {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	cfg.Path = strings.TrimSpace(cfg.Path)
	if cfg.Path == "" {
		cfg.Path = "/forward/snapshot-ready"
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		cfg.Path = "/" + cfg.Path
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	usingDefaultRun := cfg.Run == nil
	if cfg.Run == nil {
		cfg.Run = app.Run
	}
	cfg.App.Unattended = true
	if strings.TrimSpace(cfg.App.AuthorizationActor) == "" {
		cfg.App.AuthorizationActor = "webhook"
	}
	if strings.TrimSpace(cfg.App.Host) == "" {
		return nil, fmt.Errorf("Forward host is required")
	}
	if strings.TrimSpace(cfg.App.Username) == "" {
		return nil, fmt.Errorf("Forward username is required")
	}
	if strings.TrimSpace(cfg.App.Password) == "" {
		return nil, fmt.Errorf("Forward password is required")
	}
	cfg.BasicUsername = strings.TrimSpace(cfg.BasicUsername)
	cfg.BasicPassword = strings.TrimSpace(cfg.BasicPassword)
	if cfg.App.Apply && (cfg.BasicUsername == "" || cfg.BasicPassword == "") {
		return nil, fmt.Errorf("webhook Basic authentication username and password are required when apply is enabled")
	}
	if cfg.App.Apply && strings.TrimSpace(cfg.App.NetworkID) == "" {
		return nil, fmt.Errorf("configured Forward network ID is required when webhook apply is enabled")
	}
	statePath, err := resolveStatePath(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	cfg.StatePath = statePath
	state, err := loadWebhookState(statePath)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:                cfg,
		logger:             cfg.Logger,
		run:                cfg.Run,
		jobs:               make(chan Event, 32),
		state:              state,
		active:             make(map[string]snapshotWatermark),
		lookupSnapshotTime: usingDefaultRun || cfg.App.Apply || isLoopbackHost(cfg.App.Host),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc(s.cfg.Path, s.handleEvent)

	httpServer := &http.Server{Addr: s.cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go s.worker(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Printf("webhook server listening on %s%s", s.cfg.Listen, s.cfg.Path)
	err := httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queueDepth": len(s.jobs), "path": s.cfg.Path})
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	if event.Type != "" && event.Type != "SNAPSHOT_READY" {
		writeError(w, http.StatusBadRequest, "only SNAPSHOT_READY events are supported")
		return
	}
	if event.Type == "" {
		event.Type = "SNAPSHOT_READY"
	}
	if strings.TrimSpace(event.NetworkID) == "" {
		writeError(w, http.StatusBadRequest, "networkId is required")
		return
	}
	if strings.TrimSpace(event.SnapshotID) == "" {
		writeError(w, http.StatusBadRequest, "snapshotId is required")
		return
	}
	event.SetupIDs = cleanSetupIDs(append(event.SetupIDs, setupIDsFromQuery(r)...))
	var err error
	event, err = s.intersectConfiguredScope(event)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	key := eventDedupeKey(event)
	s.stateMu.Lock()
	s.pruneCompletedLocked(time.Now().UTC())
	_, duplicate := s.state.CompletedEvents[key]
	s.stateMu.Unlock()
	if duplicate {
		writeJSON(w, http.StatusAccepted, eventResponse(event, true))
		return
	}
	if err := s.rejectOlderSnapshot(r.Context(), event); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	for {
		s.stateMu.Lock()
		s.pruneCompletedLocked(time.Now().UTC())
		if _, duplicate := s.state.CompletedEvents[key]; duplicate {
			s.stateMu.Unlock()
			writeJSON(w, http.StatusAccepted, eventResponse(event, true))
			return
		}
		s.stateMu.Unlock()

		done, admitted := registerProcessAdmission(s.cfg.StatePath, key)
		if !admitted {
			select {
			case <-done:
				if err := s.reloadState(); err != nil {
					writeError(w, http.StatusServiceUnavailable, err.Error())
					return
				}
				continue
			case <-r.Context().Done():
				writeError(w, http.StatusServiceUnavailable, "matching webhook job is still in progress")
				return
			}
		}
		if err := s.reloadState(); err != nil {
			finishProcessAdmission(s.cfg.StatePath, key)
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.stateMu.Lock()
		_, duplicate := s.state.CompletedEvents[key]
		s.stateMu.Unlock()
		if duplicate {
			finishProcessAdmission(s.cfg.StatePath, key)
			writeJSON(w, http.StatusAccepted, eventResponse(event, true))
			return
		}
		select {
		case s.jobs <- event:
			writeJSON(w, http.StatusAccepted, eventResponse(event, false))
			return
		default:
			finishProcessAdmission(s.cfg.StatePath, key)
			writeError(w, http.StatusServiceUnavailable, "job queue is full")
			return
		}
	}
}

func (s *Server) authorized(r *http.Request) bool {
	basicUsername := strings.TrimSpace(s.cfg.BasicUsername)
	basicPassword := strings.TrimSpace(s.cfg.BasicPassword)
	if basicUsername == "" && basicPassword == "" {
		return !s.cfg.App.Apply
	}
	if basicUsername == "" || basicPassword == "" {
		return false
	}
	username, password, ok := r.BasicAuth()
	return ok &&
		subtle.ConstantTimeCompare([]byte(username), []byte(basicUsername)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(basicPassword)) == 1
}

func (s *Server) worker(ctx context.Context) {
	s.workerRunning.Store(true)
	defer func() {
		s.releaseQueuedAdmissions()
		s.workerRunning.Store(false)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.jobs:
			cfg := s.cfg.App
			cfg.NetworkID = event.NetworkID
			cfg.SnapshotID = event.SnapshotID
			cfg.SetupIDs = append([]string(nil), event.SetupIDs...)

			snapshotTime, snapshotTimeKnown, err := s.resolveSnapshotTime(ctx, event)
			if err != nil && cfg.Apply {
				s.logger.Printf("webhook job failed before reconciliation: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
				s.finishPending(event)
				continue
			}
			if err != nil {
				s.logger.Printf("webhook snapshot ordering unavailable for non-apply job: networkId=%s snapshotId=%s err=%v", event.NetworkID, event.SnapshotID, err)
			}
			if snapshotTimeKnown {
				if err := s.beginSnapshot(event, snapshotTime); err != nil {
					s.logger.Printf("webhook job rejected by snapshot watermark: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
					s.finishPending(event)
					continue
				}
			}
			s.logger.Printf("processing webhook event: networkId=%s snapshotId=%s setupIds=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs)
			summary, err := s.run(ctx, cfg)
			if err != nil {
				s.logger.Printf("webhook job failed: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
				s.endSnapshot(event)
				s.finishPending(event)
				continue
			}
			if err := s.recordSuccess(event, snapshotTime, snapshotTimeKnown); err != nil {
				s.logger.Printf("webhook job completed but durable state could not be recorded: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
				s.endSnapshot(event)
				s.finishPending(event)
				continue
			}
			s.endSnapshot(event)
			s.finishPending(event)
			encoded, err := json.Marshal(summary)
			if err != nil {
				s.logger.Printf("webhook job completed but summary could not be encoded: networkId=%s snapshotId=%s err=%v", event.NetworkID, event.SnapshotID, err)
				continue
			}
			s.logger.Printf("webhook job completed: %s", encoded)
		}
	}
}

func (s *Server) releaseQueuedAdmissions() {
	for {
		select {
		case event := <-s.jobs:
			s.finishPending(event)
		default:
			return
		}
	}
}

func (s *Server) intersectConfiguredScope(event Event) (Event, error) {
	event.NetworkID = strings.TrimSpace(event.NetworkID)
	event.SnapshotID = strings.TrimSpace(event.SnapshotID)
	event.ID = strings.TrimSpace(event.ID)
	event.Type = strings.TrimSpace(event.Type)

	configuredNetworkID := strings.TrimSpace(s.cfg.App.NetworkID)
	if configuredNetworkID != "" && event.NetworkID != configuredNetworkID {
		return Event{}, fmt.Errorf("event network %s is outside configured network scope %s", event.NetworkID, configuredNetworkID)
	}
	if configuredNetworkID != "" {
		event.NetworkID = configuredNetworkID
	}

	configuredSetupIDs := cleanSetupIDs(s.cfg.App.SetupIDs)
	if len(event.SetupIDs) == 0 {
		event.SetupIDs = configuredSetupIDs
		return event, nil
	}
	if len(configuredSetupIDs) == 0 {
		return event, nil
	}
	allowed := make(map[string]struct{}, len(configuredSetupIDs))
	for _, setupID := range configuredSetupIDs {
		allowed[setupID] = struct{}{}
	}
	for _, setupID := range event.SetupIDs {
		if _, ok := allowed[setupID]; !ok {
			return Event{}, fmt.Errorf("event setup %s is outside configured setup scope", setupID)
		}
	}
	return event, nil
}

func (s *Server) resolveSnapshotTime(ctx context.Context, event Event) (time.Time, bool, error) {
	if !s.lookupSnapshotTime {
		return time.Time{}, false, nil
	}
	client, err := api.NewClient(
		s.cfg.App.Host,
		s.cfg.App.APIPrefix,
		s.cfg.App.Username,
		s.cfg.App.Password,
		s.cfg.App.Insecure,
		s.cfg.App.Timeout,
	)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("create snapshot metadata client: %w", err)
	}
	snapshots, err := client.ListSnapshots(ctx, event.NetworkID)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("list snapshots for ordering: %w", err)
	}
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.ID) != event.SnapshotID {
			continue
		}
		snapshotTime, err := webhookSnapshotTimestamp(snapshot)
		if err != nil {
			return time.Time{}, false, err
		}
		return snapshotTime, true, nil
	}
	return time.Time{}, false, fmt.Errorf("snapshot %s was not found in network %s", event.SnapshotID, event.NetworkID)
}

func isLoopbackHost(rawHost string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawHost))
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func eventResponse(event Event, duplicate bool) map[string]any {
	return map[string]any{
		"accepted":   true,
		"duplicate":  duplicate,
		"networkId":  event.NetworkID,
		"snapshotId": event.SnapshotID,
		"setupIds":   event.SetupIDs,
	}
}

func setupIDsFromQuery(r *http.Request) []string {
	values := r.URL.Query()
	var setupIDs []string
	for _, key := range []string{"setupId", "setup_id", "setup-id", "setupIds", "setup_ids", "setup-ids"} {
		for _, value := range values[key] {
			for _, part := range strings.Split(value, ",") {
				setupIDs = append(setupIDs, part)
			}
		}
	}
	return cleanSetupIDs(setupIDs)
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
	sort.Strings(result)
	return result
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
