package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type ExternalIDConfig struct {
	Host       string
	Username   string
	Password   string
	NetworkID  string
	SetupID    string
	ExternalID string
	Clear      bool
	Output     string
	APIPrefix  string
	Insecure   bool
	Timeout    time.Duration
	Apply      bool
}

type ExternalIDSummary struct {
	Host                         string                 `json:"host"`
	NetworkID                    string                 `json:"network_id"`
	SetupID                      string                 `json:"setup_id"`
	Apply                        bool                   `json:"apply"`
	Patched                      bool                   `json:"patched"`
	AccountCount                 int                    `json:"account_count"`
	PreviousExternalIDConfigured bool                   `json:"previous_external_id_configured"`
	PreviousExternalIDConsistent bool                   `json:"previous_external_id_consistent"`
	TargetExternalIDConfigured   bool                   `json:"target_external_id_configured"`
	Output                       string                 `json:"output"`
	PayloadSHA256                string                 `json:"payload_sha256"`
	Payload                      ExternalIDPatchPayload `json:"payload"`
}

type ExternalIDPatchPayload struct {
	Type            string               `json:"type"`
	AssumeRoleInfos []api.AssumeRoleInfo `json:"assumeRoleInfos"`
}

func ChangeExternalID(ctx context.Context, cfg ExternalIDConfig) (*ExternalIDSummary, error) {
	setupID := strings.TrimSpace(cfg.SetupID)
	externalID := strings.TrimSpace(cfg.ExternalID)
	if setupID == "" {
		return nil, fmt.Errorf("setup ID is required")
	}
	if cfg.Clear == (externalID != "") {
		return nil, fmt.Errorf("specify exactly one of an external ID value or clear")
	}

	client, err := api.NewClient(
		cfg.Host,
		cfg.APIPrefix,
		cfg.Username,
		cfg.Password,
		cfg.Insecure,
		cfg.Timeout,
	)
	if err != nil {
		return nil, err
	}
	networkID, err := ResolveNetworkID(ctx, client, cfg.NetworkID)
	if err != nil {
		return nil, err
	}
	accounts, err := client.CloudAccounts(ctx, networkID)
	if err != nil {
		return nil, err
	}
	account, err := findAWSSetup(accounts, setupID)
	if err != nil {
		return nil, err
	}
	if len(account.AssumeRoleInfos) == 0 {
		return nil, fmt.Errorf("AWS setup %s has no assumeRoleInfos to update", setupID)
	}

	previousConfigured, previousConsistent := externalIDState(account.AssumeRoleInfos)
	infos := make([]api.AssumeRoleInfo, len(account.AssumeRoleInfos))
	copy(infos, account.AssumeRoleInfos)
	for i := range infos {
		infos[i].ExternalID = externalID
	}
	payload := ExternalIDPatchPayload{
		Type:            "AWS",
		AssumeRoleInfos: infos,
	}
	output := strings.TrimSpace(cfg.Output)
	if output == "" {
		output = "aws_external_id_payload.json"
	}
	payloads := map[string]ExternalIDPatchPayload{setupID: payload}
	output, sha, err := writeJSONPayload(output, payloads)
	if err != nil {
		return nil, err
	}

	summary := &ExternalIDSummary{
		Host:                         cfg.Host,
		NetworkID:                    networkID,
		SetupID:                      setupID,
		Apply:                        cfg.Apply,
		AccountCount:                 len(infos),
		PreviousExternalIDConfigured: previousConfigured,
		PreviousExternalIDConsistent: previousConsistent,
		TargetExternalIDConfigured:   externalID != "",
		Output:                       output,
		PayloadSHA256:                sha,
		Payload:                      payload,
	}
	if !cfg.Apply {
		return summary, nil
	}
	if _, _, err := writeJSONPayload(auditPath(output), payloads); err != nil {
		return nil, err
	}
	if err := client.PatchCloudAccount(ctx, networkID, setupID, payload); err != nil {
		return nil, fmt.Errorf("patch setup %s: %w", setupID, err)
	}
	summary.Patched = true
	return summary, nil
}

func findAWSSetup(accounts []api.CloudAccount, setupID string) (api.CloudAccount, error) {
	for _, account := range accounts {
		if account.Name != setupID {
			continue
		}
		if account.Type != "" && !strings.EqualFold(account.Type, "AWS") {
			return api.CloudAccount{}, fmt.Errorf("cloud setup %s is not an AWS setup", setupID)
		}
		return account, nil
	}
	return api.CloudAccount{}, fmt.Errorf("AWS setup %s was not found", setupID)
}

func externalIDState(infos []api.AssumeRoleInfo) (configured bool, consistent bool) {
	if len(infos) == 0 {
		return false, true
	}
	first := strings.TrimSpace(infos[0].ExternalID)
	configured = first != ""
	consistent = true
	for _, info := range infos[1:] {
		value := strings.TrimSpace(info.ExternalID)
		if value != first {
			consistent = false
		}
		if value != "" {
			configured = true
		}
	}
	return configured, consistent
}
