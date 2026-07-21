package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type ApplyPlanConfig struct {
	Host              string
	Username          string
	Password          string
	NetworkID         string
	PlanPath          string
	APIPrefix         string
	Insecure          bool
	Timeout           time.Duration
	AllowRemovals     bool
	MaxRemovals       int
	MaxRemovalPercent float64
}

type ApplyPlanSummary struct {
	Host              string   `json:"host"`
	NetworkID         string   `json:"network_id"`
	PlanPath          string   `json:"plan_path"`
	PayloadSHA256     string   `json:"payload_sha256"`
	PatchedSetupCount int      `json:"patched_setup_count"`
	PatchedSetups     []string `json:"patched_setups"`
}

func ApplyPlan(ctx context.Context, cfg ApplyPlanConfig) (*ApplyPlanSummary, error) {
	if err := validateRemovalLimitValues(cfg.MaxRemovals, cfg.MaxRemovalPercent); err != nil {
		return nil, err
	}
	client, err := api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	networkID, err := ResolveNetworkID(ctx, client, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	cfg.NetworkID = networkID
	planPath := strings.TrimSpace(cfg.PlanPath)
	if planPath == "" {
		return nil, fmt.Errorf("plan path is required")
	}
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	var payloads map[string]api.PatchPayload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("decode plan file: %w", err)
	}
	setupIDs := make([]string, 0, len(payloads))
	for setupID, payload := range payloads {
		setupID = strings.TrimSpace(setupID)
		if setupID == "" {
			return nil, fmt.Errorf("plan contains an empty setup id")
		}
		if strings.TrimSpace(payload.Name) != "" && strings.TrimSpace(payload.Name) != setupID {
			return nil, fmt.Errorf("plan setup %s has mismatched payload name %s", setupID, payload.Name)
		}
		setupIDs = append(setupIDs, setupID)
	}
	if len(setupIDs) == 0 {
		return nil, fmt.Errorf("plan contains no setup payloads")
	}
	cloudAccounts, err := client.CloudAccounts(ctx, cfg.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("load current cloud setups before apply: %w", err)
	}
	currentByName := make(map[string]api.CloudAccount, len(cloudAccounts))
	for _, account := range cloudAccounts {
		currentByName[strings.TrimSpace(account.Name)] = account
	}
	removalStats := make([]removalStat, 0, len(setupIDs))
	for _, setupID := range setupIDs {
		current, ok := currentByName[setupID]
		if !ok {
			return nil, fmt.Errorf("plan setup %s does not exist in Forward", setupID)
		}
		if err := validateCloudAccountPartition(current); err != nil {
			return nil, fmt.Errorf("setup %s: %w", setupID, err)
		}
		payload := payloads[setupID]
		planned := api.CloudAccount{Name: setupID, AssumeRoleInfos: payload.AssumeRoleInfos}
		if len(payload.Regions) > 0 {
			planned.Regions = make(map[string]api.RegionMeta, len(payload.Regions))
			for region, instant := range payload.Regions {
				planned.Regions[region] = api.RegionMeta{TestInstant: instant}
			}
		}
		if err := validateCloudAccountPartition(planned); err != nil {
			return nil, fmt.Errorf("plan setup %s: %w", setupID, err)
		}
		currentRows := currentAccounts(current.AssumeRoleInfos)
		_, removed, _ := accountDiff(currentRows, currentAccounts(payload.AssumeRoleInfos))
		removalStats = append(removalStats, removalStat{
			SetupID:         setupID,
			ConfiguredCount: len(currentRows),
			RemovedCount:    len(removed),
		})
		if len(removed) == 0 {
			continue
		}
		if extractRolePartition(current.AssumeRoleInfos) == "aws-us-gov" {
			return nil, fmt.Errorf("apply-plan cannot remove GovCloud accounts; rerun preflight/NQE with positive Organizations evidence or use sync-accounts with the authoritative manifest")
		}
		if !cfg.AllowRemovals {
			return nil, fmt.Errorf("plan removes %d account(s) from setup %s; apply-plan requires --allow-removals", len(removed), setupID)
		}
	}
	if err := validateRemovalStats(removalStats, cfg.MaxRemovals, cfg.MaxRemovalPercent); err != nil {
		return nil, err
	}
	sort.Strings(setupIDs)
	for _, setupID := range setupIDs {
		if err := client.PatchCloudAccount(ctx, cfg.NetworkID, setupID, payloads[setupID]); err != nil {
			return nil, fmt.Errorf("patch setup %s: %w", setupID, err)
		}
	}
	return &ApplyPlanSummary{
		Host:              cfg.Host,
		NetworkID:         cfg.NetworkID,
		PlanPath:          planPath,
		PayloadSHA256:     fmt.Sprintf("%x", sha256.Sum256(data)),
		PatchedSetupCount: len(setupIDs),
		PatchedSetups:     setupIDs,
	}, nil
}
