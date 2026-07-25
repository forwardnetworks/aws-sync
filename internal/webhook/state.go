package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

const (
	previousWebhookStateVersion = 1
	webhookStateVersion         = 2
	dedupeRetention             = 24 * time.Hour
	webhookMaxAttempts          = 5
	webhookRetryBaseDelay       = time.Second
	webhookRetryMaxDelay        = 30 * time.Second
	webhookQueueCapacity        = 32
)

const (
	webhookJobQueued   = "queued"
	webhookJobInFlight = "in_flight"
)

type webhookState struct {
	Version          int                               `json:"version"`
	CompletedEvents  map[string]time.Time              `json:"completed_events"`
	Watermarks       map[string]snapshotWatermark      `json:"snapshot_watermarks"`
	PendingEvents    map[string]pendingWebhookEvent    `json:"pending_events"`
	DeadLetterEvents map[string]deadLetterWebhookEvent `json:"dead_letter_events"`
}

type pendingWebhookEvent struct {
	Event         Event      `json:"event"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	AcceptedAt    time.Time  `json:"accepted_at"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

type deadLetterWebhookEvent struct {
	Event          Event      `json:"event"`
	Attempts       int        `json:"attempts"`
	AcceptedAt     time.Time  `json:"accepted_at"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	DeadLetteredAt time.Time  `json:"dead_lettered_at"`
	LastError      string     `json:"last_error"`
}

type snapshotWatermark struct {
	NetworkID   string    `json:"network_id"`
	SetupID     string    `json:"setup_id"`
	SnapshotID  string    `json:"snapshot_id"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	CompletedAt time.Time `json:"completed_at"`
}

var processAdmissions = struct {
	sync.Mutex
	byStatePath map[string]map[string]chan struct{}
}{
	byStatePath: make(map[string]map[string]chan struct{}),
}

func resolveStatePath(configured string) (string, error) {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve webhook state directory: %w", err)
	}
	return filepath.Join(configDir, "awssync", "webhook-state.json"), nil
}

func loadWebhookState(path string) (webhookState, error) {
	state := newWebhookState()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return webhookState{}, fmt.Errorf("read webhook state %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return webhookState{}, fmt.Errorf("decode webhook state %s: %w", path, err)
	}
	migrated := false
	switch state.Version {
	case previousWebhookStateVersion:
		state.Version = webhookStateVersion
		migrated = true
	case webhookStateVersion:
	default:
		return webhookState{}, fmt.Errorf("webhook state %s has version %d; want %d or upgradeable version %d", path, state.Version, webhookStateVersion, previousWebhookStateVersion)
	}
	if state.CompletedEvents == nil {
		state.CompletedEvents = make(map[string]time.Time)
	}
	if state.Watermarks == nil {
		state.Watermarks = make(map[string]snapshotWatermark)
	}
	if state.PendingEvents == nil {
		state.PendingEvents = make(map[string]pendingWebhookEvent)
	}
	if state.DeadLetterEvents == nil {
		state.DeadLetterEvents = make(map[string]deadLetterWebhookEvent)
	}
	for key, job := range state.PendingEvents {
		if job.Status != webhookJobQueued && job.Status != webhookJobInFlight {
			return webhookState{}, fmt.Errorf("webhook state %s pending event %q has invalid status %q", path, key, job.Status)
		}
		if job.Attempts < 0 {
			return webhookState{}, fmt.Errorf("webhook state %s pending event %q has negative attempts", path, key)
		}
		if key != eventDedupeKey(job.Event) {
			return webhookState{}, fmt.Errorf("webhook state %s pending event %q does not match its scoped event key", path, key)
		}
	}
	for key, job := range state.DeadLetterEvents {
		if key != eventDedupeKey(job.Event) {
			return webhookState{}, fmt.Errorf("webhook state %s dead-letter event %q does not match its scoped event key", path, key)
		}
	}
	if migrated {
		if err := persistWebhookState(path, state); err != nil {
			return webhookState{}, fmt.Errorf("upgrade webhook state %s from version %d: %w", path, previousWebhookStateVersion, err)
		}
	}
	return state, nil
}

func newWebhookState() webhookState {
	return webhookState{
		Version:          webhookStateVersion,
		CompletedEvents:  make(map[string]time.Time),
		Watermarks:       make(map[string]snapshotWatermark),
		PendingEvents:    make(map[string]pendingWebhookEvent),
		DeadLetterEvents: make(map[string]deadLetterWebhookEvent),
	}
}

func (s *Server) rejectOlderSnapshot(ctx context.Context, event Event) error {
	barrier, ok := s.snapshotBarrier(event)
	if !ok {
		return nil
	}
	snapshotAt, known, err := s.resolveSnapshotTime(ctx, event)
	if err != nil {
		return fmt.Errorf("validate snapshot ordering: %w", err)
	}
	if !known {
		return fmt.Errorf("snapshot ordering metadata is unavailable while watermark %s is active", barrier.SnapshotID)
	}
	if snapshotAt.Before(barrier.SnapshotAt) {
		return olderSnapshotError(event, snapshotAt, barrier)
	}
	return nil
}

func (s *Server) beginSnapshot(event Event, snapshotAt time.Time) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if barrier, ok := s.snapshotBarrierLocked(event); ok && snapshotAt.Before(barrier.SnapshotAt) {
		return olderSnapshotError(event, snapshotAt, barrier)
	}
	mark := snapshotWatermark{
		NetworkID:  event.NetworkID,
		SnapshotID: event.SnapshotID,
		SnapshotAt: snapshotAt,
	}
	for _, key := range eventWatermarkKeys(event) {
		copy := mark
		copy.SetupID = watermarkSetupID(key)
		s.active[key] = copy
	}
	return nil
}

func (s *Server) endSnapshot(event Event) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	for _, key := range eventWatermarkKeys(event) {
		delete(s.active, key)
	}
}

func (s *Server) snapshotBarrier(event Event) (snapshotWatermark, bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.snapshotBarrierLocked(event)
}

func (s *Server) snapshotBarrierLocked(event Event) (snapshotWatermark, bool) {
	var (
		barrier snapshotWatermark
		found   bool
	)
	consider := func(mark snapshotWatermark) {
		if !found || mark.SnapshotAt.After(barrier.SnapshotAt) {
			barrier = mark
			found = true
		}
	}
	keys := eventWatermarkKeys(event)
	for _, key := range keys {
		if mark, ok := s.state.Watermarks[key]; ok {
			consider(mark)
		}
		if mark, ok := s.active[key]; ok {
			consider(mark)
		}
	}
	networkPrefix := event.NetworkID + "\x1f"
	if len(event.SetupIDs) == 0 {
		for key, mark := range s.state.Watermarks {
			if strings.HasPrefix(key, networkPrefix) {
				consider(mark)
			}
		}
		for key, mark := range s.active {
			if strings.HasPrefix(key, networkPrefix) {
				consider(mark)
			}
		}
	} else {
		wildcard := watermarkKey(event.NetworkID, "*")
		if mark, ok := s.state.Watermarks[wildcard]; ok {
			consider(mark)
		}
		if mark, ok := s.active[wildcard]; ok {
			consider(mark)
		}
	}
	return barrier, found
}

func (s *Server) recordSuccess(event Event, snapshotAt time.Time, snapshotTimeKnown bool) error {
	now := time.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	next := cloneWebhookState(s.state)
	for key, completedAt := range next.CompletedEvents {
		if completedAt.Before(now.Add(-dedupeRetention)) {
			delete(next.CompletedEvents, key)
		}
	}
	key := eventDedupeKey(event)
	next.CompletedEvents[key] = now
	delete(next.PendingEvents, key)
	delete(next.DeadLetterEvents, key)
	if snapshotTimeKnown {
		for _, key := range eventWatermarkKeys(event) {
			current, exists := next.Watermarks[key]
			if exists && current.SnapshotAt.After(snapshotAt) {
				continue
			}
			next.Watermarks[key] = snapshotWatermark{
				NetworkID:   event.NetworkID,
				SetupID:     watermarkSetupID(key),
				SnapshotID:  event.SnapshotID,
				SnapshotAt:  snapshotAt,
				CompletedAt: now,
			}
		}
	}
	if err := s.persistState(s.cfg.StatePath, next); err != nil {
		return err
	}
	s.state = next
	s.invalidateScheduleLocked(key)
	delete(s.queued, key)
	return nil
}

func registerProcessAdmission(statePath, key string) (<-chan struct{}, bool) {
	processAdmissions.Lock()
	defer processAdmissions.Unlock()
	admissions := processAdmissions.byStatePath[statePath]
	if admissions == nil {
		admissions = make(map[string]chan struct{})
		processAdmissions.byStatePath[statePath] = admissions
	}
	if done, exists := admissions[key]; exists {
		return done, false
	}
	done := make(chan struct{})
	admissions[key] = done
	return done, true
}

func finishProcessAdmission(statePath, key string) {
	processAdmissions.Lock()
	defer processAdmissions.Unlock()
	admissions := processAdmissions.byStatePath[statePath]
	if admissions == nil {
		return
	}
	if done, exists := admissions[key]; exists {
		delete(admissions, key)
		close(done)
	}
	if len(admissions) == 0 {
		delete(processAdmissions.byStatePath, statePath)
	}
}

func (s *Server) reloadState() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	state, err := loadWebhookState(s.cfg.StatePath)
	if err != nil {
		return err
	}
	s.state = state
	return nil
}

func (s *Server) pruneCompletedLocked(now time.Time) {
	cutoff := now.Add(-dedupeRetention)
	for key, completedAt := range s.state.CompletedEvents {
		if completedAt.Before(cutoff) {
			delete(s.state.CompletedEvents, key)
		}
	}
}

func persistWebhookState(path string, state webhookState) (err error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode webhook state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create webhook state directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create webhook state temp file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return err
	}
	return nil
}

func cloneWebhookState(state webhookState) webhookState {
	clone := newWebhookState()
	for key, completedAt := range state.CompletedEvents {
		clone.CompletedEvents[key] = completedAt
	}
	for key, watermark := range state.Watermarks {
		clone.Watermarks[key] = watermark
	}
	for key, job := range state.PendingEvents {
		clone.PendingEvents[key] = clonePendingWebhookEvent(job)
	}
	for key, job := range state.DeadLetterEvents {
		clone.DeadLetterEvents[key] = cloneDeadLetterWebhookEvent(job)
	}
	return clone
}

func clonePendingWebhookEvent(job pendingWebhookEvent) pendingWebhookEvent {
	job.Event.SetupIDs = append([]string(nil), job.Event.SetupIDs...)
	job.LastAttemptAt = cloneTimePointer(job.LastAttemptAt)
	job.NextAttemptAt = cloneTimePointer(job.NextAttemptAt)
	return job
}

func cloneDeadLetterWebhookEvent(job deadLetterWebhookEvent) deadLetterWebhookEvent {
	job.Event.SetupIDs = append([]string(nil), job.Event.SetupIDs...)
	job.LastAttemptAt = cloneTimePointer(job.LastAttemptAt)
	return job
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (s *Server) recoverInFlightJobs() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	next := cloneWebhookState(s.state)
	changed := false
	for key, job := range next.PendingEvents {
		if job.Status != webhookJobInFlight {
			continue
		}
		changed = true
		crashError := fmt.Sprintf("process exited while attempt %d was in-flight; completion is ambiguous", job.Attempts)
		if job.Attempts >= s.maxAttempts {
			delete(next.PendingEvents, key)
			next.DeadLetterEvents[key] = deadLetterWebhookEvent{
				Event:          job.Event,
				Attempts:       job.Attempts,
				AcceptedAt:     job.AcceptedAt,
				LastAttemptAt:  cloneTimePointer(job.LastAttemptAt),
				DeadLetteredAt: time.Now().UTC(),
				LastError:      crashError,
			}
			continue
		}
		job.Status = webhookJobQueued
		job.LastError = crashError
		nextAttempt := time.Now().UTC()
		if job.LastAttemptAt != nil {
			nextAttempt = job.LastAttemptAt.Add(s.retryDelay(job.Attempts))
		}
		job.NextAttemptAt = &nextAttempt
		next.PendingEvents[key] = job
	}
	if !changed {
		return nil
	}
	if err := s.persistState(s.cfg.StatePath, next); err != nil {
		return fmt.Errorf("recover in-flight webhook jobs: %w", err)
	}
	s.state = next
	return nil
}

func (s *Server) markJobInFlight(event Event) (pendingWebhookEvent, bool, error) {
	key := eventDedupeKey(event)
	now := time.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	delete(s.queued, key)
	s.invalidateScheduleLocked(key)
	job, exists := s.state.PendingEvents[key]
	if !exists {
		return pendingWebhookEvent{}, false, nil
	}
	next := cloneWebhookState(s.state)
	job.Attempts++
	job.Status = webhookJobInFlight
	job.LastAttemptAt = &now
	job.NextAttemptAt = nil
	next.PendingEvents[key] = job
	if err := s.persistState(s.cfg.StatePath, next); err != nil {
		return pendingWebhookEvent{}, true, err
	}
	s.state = next
	return job, true, nil
}

func (s *Server) recordJobFailure(job pendingWebhookEvent, runErr error) (*time.Time, bool, error) {
	key := eventDedupeKey(job.Event)
	now := time.Now().UTC()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	current, exists := s.state.PendingEvents[key]
	if !exists {
		return nil, false, nil
	}
	next := cloneWebhookState(s.state)
	current.LastError = runErr.Error()
	current.LastAttemptAt = cloneTimePointer(job.LastAttemptAt)
	if current.Attempts >= s.maxAttempts {
		delete(next.PendingEvents, key)
		next.DeadLetterEvents[key] = deadLetterWebhookEvent{
			Event:          current.Event,
			Attempts:       current.Attempts,
			AcceptedAt:     current.AcceptedAt,
			LastAttemptAt:  cloneTimePointer(current.LastAttemptAt),
			DeadLetteredAt: now,
			LastError:      current.LastError,
		}
		if err := s.persistState(s.cfg.StatePath, next); err != nil {
			return nil, false, err
		}
		s.state = next
		s.invalidateScheduleLocked(key)
		delete(s.queued, key)
		return nil, true, nil
	}

	nextAttempt := now.Add(s.retryDelay(current.Attempts))
	current.Status = webhookJobQueued
	current.NextAttemptAt = &nextAttempt
	next.PendingEvents[key] = current
	if err := s.persistState(s.cfg.StatePath, next); err != nil {
		return nil, false, err
	}
	s.state = next
	return &nextAttempt, false, nil
}

func (s *Server) retryDelay(failedAttempts int) time.Duration {
	delay := s.retryBaseDelay
	for attempt := 1; attempt < failedAttempts && delay < s.retryMaxDelay; attempt++ {
		delay *= 2
		if delay > s.retryMaxDelay {
			delay = s.retryMaxDelay
		}
	}
	return delay
}

func eventDedupeKey(event Event) string {
	return strings.Join([]string{
		strings.TrimSpace(event.Type),
		strings.TrimSpace(event.NetworkID),
		strings.TrimSpace(event.SnapshotID),
		strings.Join(cleanSetupIDs(event.SetupIDs), ","),
		strings.TrimSpace(event.ID),
	}, "\x1f")
}

func eventWatermarkKeys(event Event) []string {
	setupIDs := cleanSetupIDs(event.SetupIDs)
	if len(setupIDs) == 0 {
		return []string{watermarkKey(event.NetworkID, "*")}
	}
	keys := make([]string, 0, len(setupIDs))
	for _, setupID := range setupIDs {
		keys = append(keys, watermarkKey(event.NetworkID, setupID))
	}
	return keys
}

func watermarkKey(networkID, setupID string) string {
	return strings.TrimSpace(networkID) + "\x1f" + strings.TrimSpace(setupID)
}

func watermarkSetupID(key string) string {
	parts := strings.SplitN(key, "\x1f", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func olderSnapshotError(event Event, snapshotAt time.Time, barrier snapshotWatermark) error {
	return fmt.Errorf(
		"snapshot %s at %s is older than applied/in-progress snapshot %s at %s for network/setup scope",
		event.SnapshotID,
		snapshotAt.Format(time.RFC3339Nano),
		barrier.SnapshotID,
		barrier.SnapshotAt.Format(time.RFC3339Nano),
	)
}

func webhookSnapshotTimestamp(snapshot api.SnapshotInfo) (time.Time, error) {
	for _, value := range []string{snapshot.CreatedAt, snapshot.ProcessedAt} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("snapshot %s has invalid timestamp %q: %w", snapshot.ID, value, err)
		}
		return parsed, nil
	}
	return time.Time{}, fmt.Errorf("snapshot %s has no processedAt or createdAt timestamp", snapshot.ID)
}
