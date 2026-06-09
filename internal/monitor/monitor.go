package monitor

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type StatusResult struct {
	NetworkID               string             `json:"network_id"`
	LatestProcessedSnapshot *api.SnapshotInfo  `json:"latest_processed_snapshot,omitempty"`
	Snapshots               []api.SnapshotInfo `json:"snapshots"`
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
	}, nil
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
	if desiredState == "" {
		desiredState = "PROCESSED"
	}
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}

	for {
		snapshots, err := client.ListSnapshots(ctx, networkID)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range snapshots {
			if snapshot.ID != snapshotID {
				continue
			}
			if snapshot.State == desiredState {
				return &WaitResult{
					NetworkID:    networkID,
					Snapshot:     snapshot,
					DesiredState: desiredState,
				}, nil
			}
			if slices.Contains([]string{"FAILED", "ARCHIVED"}, snapshot.State) {
				return nil, fmt.Errorf("snapshot %s entered terminal state %s before reaching %s", snapshotID, snapshot.State, desiredState)
			}
			break
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
