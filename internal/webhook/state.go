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
	webhookStateVersion = 1
	dedupeRetention     = 24 * time.Hour
)

type webhookState struct {
	Version         int                          `json:"version"`
	CompletedEvents map[string]time.Time         `json:"completed_events"`
	Watermarks      map[string]snapshotWatermark `json:"snapshot_watermarks"`
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
	if state.Version != webhookStateVersion {
		return webhookState{}, fmt.Errorf("webhook state %s has version %d; want %d", path, state.Version, webhookStateVersion)
	}
	if state.CompletedEvents == nil {
		state.CompletedEvents = make(map[string]time.Time)
	}
	if state.Watermarks == nil {
		state.Watermarks = make(map[string]snapshotWatermark)
	}
	return state, nil
}

func newWebhookState() webhookState {
	return webhookState{
		Version:         webhookStateVersion,
		CompletedEvents: make(map[string]time.Time),
		Watermarks:      make(map[string]snapshotWatermark),
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
	next.CompletedEvents[eventDedupeKey(event)] = now
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
	if err := persistWebhookState(s.cfg.StatePath, next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Server) finishPending(event Event) {
	key := eventDedupeKey(event)
	finishProcessAdmission(s.cfg.StatePath, key)
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
	return clone
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
