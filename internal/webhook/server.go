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
	cfg          Config
	logger       *log.Logger
	run          RunFunc
	persistState func(string, webhookState) error
	jobs         chan Event

	stateMu            sync.Mutex
	state              webhookState
	active             map[string]snapshotWatermark
	queued             map[string]bool
	scheduleGeneration map[string]uint64
	lookupSnapshotTime bool
	workerRunning      atomic.Bool
	workerDone         chan struct{}
	maxAttempts        int
	retryBaseDelay     time.Duration
	retryMaxDelay      time.Duration
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

	server := &Server{
		cfg:                cfg,
		logger:             cfg.Logger,
		run:                cfg.Run,
		persistState:       persistWebhookState,
		jobs:               make(chan Event, webhookQueueCapacity),
		state:              state,
		active:             make(map[string]snapshotWatermark),
		queued:             make(map[string]bool),
		scheduleGeneration: make(map[string]uint64),
		lookupSnapshotTime: usingDefaultRun || cfg.App.Apply || isLoopbackHost(cfg.App.Host),
		workerDone:         make(chan struct{}),
		maxAttempts:        webhookMaxAttempts,
		retryBaseDelay:     webhookRetryBaseDelay,
		retryMaxDelay:      webhookRetryMaxDelay,
	}
	if err := server.recoverInFlightJobs(); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc(s.cfg.Path, s.handleEvent)

	httpServer := &http.Server{Addr: s.cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	workerCtx, stopWorker := context.WithCancel(ctx)
	go s.worker(workerCtx)
	go func() {
		<-workerCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Printf("webhook server listening on %s%s", s.cfg.Listen, s.cfg.Path)
	err := httpServer.ListenAndServe()
	stopWorker()
	s.waitForWorker()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.stateMu.Lock()
	pendingDepth := len(s.state.PendingEvents)
	deadLetterDepth := len(s.state.DeadLetterEvents)
	s.stateMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"queueDepth":      len(s.jobs),
		"pendingDepth":    pendingDepth,
		"deadLetterDepth": deadLetterDepth,
		"path":            s.cfg.Path,
	})
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
		duplicate, err := s.admitEvent(event)
		if err != nil {
			finishProcessAdmission(s.cfg.StatePath, key)
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if duplicate {
			finishProcessAdmission(s.cfg.StatePath, key)
		}
		writeJSON(w, http.StatusAccepted, eventResponse(event, duplicate))
		return
	}
}

func (s *Server) admitEvent(event Event) (bool, error) {
	key := eventDedupeKey(event)
	now := time.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.pruneCompletedLocked(now)
	if _, duplicate := s.state.CompletedEvents[key]; duplicate {
		return true, nil
	}
	if job, pending := s.state.PendingEvents[key]; pending {
		if job.Status == webhookJobQueued && !s.queued[key] {
			select {
			case s.jobs <- job.Event:
				s.queued[key] = true
				s.invalidateScheduleLocked(key)
			default:
			}
		}
		return true, nil
	}
	if len(s.state.PendingEvents) >= webhookQueueCapacity {
		return false, fmt.Errorf("job queue is full")
	}

	previous := cloneWebhookState(s.state)
	next := cloneWebhookState(s.state)
	delete(next.DeadLetterEvents, key)
	next.PendingEvents[key] = pendingWebhookEvent{
		Event:      event,
		Status:     webhookJobQueued,
		AcceptedAt: now,
	}
	if err := s.persistState(s.cfg.StatePath, next); err != nil {
		return false, fmt.Errorf("persist accepted webhook event: %w", err)
	}
	s.state = next
	select {
	case s.jobs <- event:
		s.queued[key] = true
		return false, nil
	default:
		if err := s.persistState(s.cfg.StatePath, previous); err != nil {
			return false, fmt.Errorf("job queue is full; event remains durably pending because admission rollback failed: %w", err)
		}
		s.state = previous
		return false, fmt.Errorf("job queue is full")
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
		s.releasePendingAdmissions()
		s.workerRunning.Store(false)
		close(s.workerDone)
	}()
	s.startPendingJobs(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.jobs:
			s.processJob(ctx, event)
		}
	}
}

func (s *Server) waitForWorker() {
	<-s.workerDone
}

func (s *Server) processJob(ctx context.Context, event Event) {
	defer finishProcessAdmission(s.cfg.StatePath, eventDedupeKey(event))
	job, exists, err := s.markJobInFlight(event)
	if err != nil {
		s.logger.Printf("webhook job could not be marked in-flight: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, event.SetupIDs, err)
		s.scheduleJob(ctx, event, time.Now().UTC().Add(s.retryBaseDelay))
		return
	}
	if !exists {
		return
	}
	event = job.Event
	cfg := s.cfg.App
	cfg.NetworkID = event.NetworkID
	cfg.SnapshotID = event.SnapshotID
	cfg.SetupIDs = append([]string(nil), event.SetupIDs...)

	snapshotTime, snapshotTimeKnown, err := s.resolveSnapshotTime(ctx, event)
	if err != nil && cfg.Apply {
		s.failJob(ctx, job, fmt.Errorf("resolve snapshot ordering metadata: %w", err))
		return
	}
	if err != nil {
		s.logger.Printf("webhook snapshot ordering unavailable for non-apply job: networkId=%s snapshotId=%s err=%v", event.NetworkID, event.SnapshotID, err)
	}
	if snapshotTimeKnown {
		if err := s.beginSnapshot(event, snapshotTime); err != nil {
			s.failJob(ctx, job, err)
			return
		}
		defer s.endSnapshot(event)
	}

	s.logger.Printf("processing webhook event: networkId=%s snapshotId=%s setupIds=%v attempt=%d/%d", event.NetworkID, event.SnapshotID, cfg.SetupIDs, job.Attempts, s.maxAttempts)
	summary, err := s.run(ctx, cfg)
	if err != nil {
		s.failJob(ctx, job, err)
		return
	}
	if err := s.recordSuccess(event, snapshotTime, snapshotTimeKnown); err != nil {
		s.logger.Printf("webhook job completed but durable state could not be recorded; leaving it in-flight for restart recovery: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, cfg.SetupIDs, err)
		return
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		s.logger.Printf("webhook job completed but summary could not be encoded: networkId=%s snapshotId=%s err=%v", event.NetworkID, event.SnapshotID, err)
		return
	}
	s.logger.Printf("webhook job completed: %s", encoded)
}

func (s *Server) releasePendingAdmissions() {
	s.stateMu.Lock()
	keys := make([]string, 0, len(s.state.PendingEvents))
	for key := range s.state.PendingEvents {
		keys = append(keys, key)
	}
	s.stateMu.Unlock()
	for _, key := range keys {
		finishProcessAdmission(s.cfg.StatePath, key)
	}
}

func (s *Server) failJob(ctx context.Context, job pendingWebhookEvent, runErr error) {
	event := job.Event
	if ctx.Err() != nil {
		s.logger.Printf("webhook job interrupted during shutdown; leaving it in-flight for restart recovery: networkId=%s snapshotId=%s setupIds=%v err=%v", event.NetworkID, event.SnapshotID, event.SetupIDs, runErr)
		return
	}
	nextAttempt, deadLettered, err := s.recordJobFailure(job, runErr)
	if err != nil {
		s.logger.Printf("webhook job failed and durable retry state could not be recorded; leaving it in-flight for restart recovery: networkId=%s snapshotId=%s setupIds=%v err=%v stateErr=%v", event.NetworkID, event.SnapshotID, event.SetupIDs, runErr, err)
		return
	}
	if deadLettered {
		s.logger.Printf("webhook job exhausted %d attempts and was dead-lettered: networkId=%s snapshotId=%s setupIds=%v err=%v", s.maxAttempts, event.NetworkID, event.SnapshotID, event.SetupIDs, runErr)
		return
	}
	s.logger.Printf("webhook job failed; retry scheduled for %s: networkId=%s snapshotId=%s setupIds=%v err=%v", nextAttempt.Format(time.RFC3339Nano), event.NetworkID, event.SnapshotID, event.SetupIDs, runErr)
	s.scheduleJob(ctx, event, *nextAttempt)
}

func (s *Server) startPendingJobs(ctx context.Context) {
	s.stateMu.Lock()
	jobs := make([]pendingWebhookEvent, 0, len(s.state.PendingEvents))
	for _, job := range s.state.PendingEvents {
		jobs = append(jobs, clonePendingWebhookEvent(job))
	}
	s.stateMu.Unlock()
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].AcceptedAt.Before(jobs[j].AcceptedAt)
	})
	for _, job := range jobs {
		when := time.Now().UTC()
		if job.NextAttemptAt != nil {
			when = *job.NextAttemptAt
		}
		s.scheduleJob(ctx, job.Event, when)
	}
}

func (s *Server) scheduleJob(ctx context.Context, event Event, when time.Time) {
	key := eventDedupeKey(event)
	s.stateMu.Lock()
	s.scheduleGeneration[key]++
	generation := s.scheduleGeneration[key]
	s.stateMu.Unlock()

	go func() {
		delay := time.Until(when)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.enqueueScheduledJob(ctx, event, generation)
	}()
}

func (s *Server) enqueueScheduledJob(ctx context.Context, event Event, generation uint64) {
	key := eventDedupeKey(event)
	s.stateMu.Lock()
	job, exists := s.state.PendingEvents[key]
	if !exists || job.Status != webhookJobQueued || s.queued[key] || s.scheduleGeneration[key] != generation {
		s.stateMu.Unlock()
		return
	}
	select {
	case s.jobs <- job.Event:
		s.queued[key] = true
		s.stateMu.Unlock()
		return
	default:
		s.stateMu.Unlock()
	}
	if ctx.Err() == nil {
		s.scheduleJob(ctx, event, time.Now().UTC().Add(s.retryBaseDelay))
	}
}

func (s *Server) invalidateScheduleLocked(key string) {
	s.scheduleGeneration[key]++
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
