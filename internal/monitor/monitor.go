package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type StatusResult struct {
	NetworkID               string             `json:"network_id"`
	LatestProcessedSnapshot *api.SnapshotInfo  `json:"latest_processed_snapshot,omitempty"`
	Snapshots               []api.SnapshotInfo `json:"snapshots"`
	ObservationAtomic       bool               `json:"observation_atomic"`
	LatestListConsistent    bool               `json:"latest_list_consistent"`
	ObservationWarning      string             `json:"observation_warning"`
}

type WaitResult struct {
	NetworkID               string            `json:"network_id"`
	Snapshot                api.SnapshotInfo  `json:"snapshot"`
	DesiredState            string            `json:"desired_state"`
	LatestProcessedSnapshot *api.SnapshotInfo `json:"latest_processed_snapshot,omitempty"`
}

func Status(ctx context.Context, client *api.Client, networkID, snapshotID string) (*StatusResult, error) {
	latest, err := client.LatestProcessedSnapshot(ctx, networkID)
	if err != nil {
		return nil, err
	}
	snapshots, err := client.ListSnapshots(ctx, networkID)
	if err != nil {
		return nil, err
	}
	latestListConsistent, observationWarning := compareLatestAndList(latest, snapshots)
	if snapshotID != "" {
		filtered := make([]api.SnapshotInfo, 0, 1)
		for _, snapshot := range snapshots {
			if snapshot.ID == snapshotID {
				filtered = append(filtered, snapshot)
				break
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("snapshot %s not found in network %s", snapshotID, networkID)
		}
		snapshots = filtered
	}
	return &StatusResult{
		NetworkID:               networkID,
		LatestProcessedSnapshot: latest,
		Snapshots:               snapshots,
		ObservationAtomic:       false,
		LatestListConsistent:    latestListConsistent,
		ObservationWarning:      observationWarning,
	}, nil
}

func compareLatestAndList(latest *api.SnapshotInfo, snapshots []api.SnapshotInfo) (bool, string) {
	for _, snapshot := range snapshots {
		if snapshot.ID != latest.ID {
			continue
		}
		if snapshot.State != "" && latest.State != "" && !strings.EqualFold(strings.TrimSpace(snapshot.State), strings.TrimSpace(latest.State)) {
			return false, fmt.Sprintf(
				"latest processed endpoint reported snapshot %s in state %s, while the snapshot list reported state %s; the endpoints are separate reads and may have observed different points in time",
				latest.ID,
				latest.State,
				snapshot.State,
			)
		}
		return true, "latest processed and snapshot list are separate API reads; matching responses do not guarantee a point-in-time atomic observation"
	}
	return false, fmt.Sprintf(
		"latest processed endpoint reported snapshot %s, but it was absent from the snapshot list; the endpoints are separate reads and may have observed different points in time",
		latest.ID,
	)
}

func Wait(
	ctx context.Context,
	client *api.Client,
	networkID, snapshotID, desiredState string,
	pollInterval time.Duration,
) (*WaitResult, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("snapshot id is required")
	}
	desiredState = normalizeSnapshotState(desiredState)
	if desiredState == "" {
		desiredState = "PROCESSED"
	}
	if !recognizedSnapshotState(desiredState) {
		return nil, fmt.Errorf(
			"desired snapshot state %q is unrecognized; recognized states are PROCESSING, PROCESSED, FAILED, and ARCHIVED",
			desiredState,
		)
	}
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}

	for {
		snapshots, err := client.ListSnapshots(ctx, networkID)
		if err != nil {
			return nil, err
		}
		found := false
		for _, snapshot := range snapshots {
			if snapshot.ID != snapshotID {
				continue
			}
			found = true
			state := normalizeSnapshotState(snapshot.State)
			if !recognizedSnapshotState(state) {
				return nil, fmt.Errorf(
					"snapshot %s has unrecognized state %q; recognized states are PROCESSING, PROCESSED, FAILED, and ARCHIVED",
					snapshotID,
					snapshot.State,
				)
			}
			if state == desiredState {
				return &WaitResult{
					NetworkID:    networkID,
					Snapshot:     snapshot,
					DesiredState: desiredState,
				}, nil
			}
			switch state {
			case "FAILED", "ARCHIVED":
				return nil, fmt.Errorf("snapshot %s entered terminal state %s before reaching %s", snapshotID, snapshot.State, desiredState)
			case "PROCESSING", "PROCESSED":
			}
			break
		}
		if !found {
			return nil, fmt.Errorf("snapshot %s not found in network %s", snapshotID, networkID)
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func normalizeSnapshotState(state string) string {
	return strings.ToUpper(strings.TrimSpace(state))
}

func recognizedSnapshotState(state string) bool {
	switch state {
	case "PROCESSING", "PROCESSED", "FAILED", "ARCHIVED":
		return true
	default:
		return false
	}
}
