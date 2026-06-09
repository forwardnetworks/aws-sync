package webhook

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/app"
)

type RunFunc func(context.Context, app.Config) (*app.Summary, error)

type Config struct {
	Listen        string
	Path          string
	BasicUsername string
	BasicPassword string
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

	seenMu sync.Mutex
	seen   map[string]time.Time
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
	if cfg.Run == nil {
		cfg.Run = app.Run
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

	return &Server{
		cfg:    cfg,
		logger: cfg.Logger,
		run:    cfg.Run,
		jobs:   make(chan Event, 32),
		seen:   make(map[string]time.Time),
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
	if strings.TrimSpace(event.NetworkID) == "" {
		writeError(w, http.StatusBadRequest, "networkId is required")
		return
	}
	if strings.TrimSpace(event.SnapshotID) == "" {
		writeError(w, http.StatusBadRequest, "snapshotId is required")
		return
	}
	event.SetupIDs = cleanSetupIDs(append(event.SetupIDs, setupIDsFromQuery(r)...))
	if s.seenBefore(event) {
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "duplicate": true, "networkId": event.NetworkID, "snapshotId": event.SnapshotID, "setupIds": event.SetupIDs})
		return
	}
	select {
	case s.jobs <- event:
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "duplicate": false, "networkId": event.NetworkID, "snapshotId": event.SnapshotID, "setupIds": event.SetupIDs})
	default:
		writeError(w, http.StatusServiceUnavailable, "job queue is full")
	}
}

func (s *Server) authorized(r *http.Request) bool {
	basicUsername := strings.TrimSpace(s.cfg.BasicUsername)
	basicPassword := strings.TrimSpace(s.cfg.BasicPassword)
	if basicUsername == "" && basicPassword == "" {
		return true
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
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.jobs:
			cfg := s.cfg.App
			cfg.NetworkID = event.NetworkID
			cfg.SnapshotID = event.SnapshotID
			if len(event.SetupIDs) > 0 {
				cfg.SetupIDs = event.SetupIDs
			}
			s.logger.Printf("processing webhook event: networkId=%s snapshotId=%s setupIds=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs)
			summary, err := s.run(ctx, cfg)
			if err != nil {
				s.logger.Printf("webhook job failed: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
				continue
			}
			encoded, err := json.Marshal(summary)
			if err != nil {
				s.logger.Printf("webhook job completed but summary could not be encoded: networkId=%s snapshotId=%s err=%v", event.NetworkID, event.SnapshotID, err)
				continue
			}
			s.logger.Printf("webhook job completed: %s", encoded)
		}
	}
}

func (s *Server) seenBefore(event Event) bool {
	key := event.ID
	if strings.TrimSpace(key) == "" {
		key = fmt.Sprintf("%s:%s:%s:%s", strings.TrimSpace(event.Type), strings.TrimSpace(event.NetworkID), strings.TrimSpace(event.SnapshotID), strings.Join(cleanSetupIDs(event.SetupIDs), ","))
	}
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)

	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	for k, seenAt := range s.seen {
		if seenAt.Before(cutoff) {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[key]; ok {
		return true
	}
	s.seen[key] = now
	return false
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
