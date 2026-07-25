package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

type ExternalIDConfig struct {
	Host               string
	Username           string
	Password           string
	NetworkID          string
	SetupID            string
	AccountIDs         []string
	ExternalID         string
	Clear              bool
	ExternalIDFile     string
	Output             string
	APIPrefix          string
	Insecure           bool
	Timeout            time.Duration
	Apply              bool
	ConfirmApply       func(planDigest string) error
	AuthorizationActor string
	Unattended         bool
}

type ExternalIDSummary struct {
	Host                         string                 `json:"host"`
	NetworkID                    string                 `json:"network_id"`
	SetupID                      string                 `json:"setup_id"`
	Apply                        bool                   `json:"apply"`
	Patched                      bool                   `json:"patched"`
	Mode                         string                 `json:"mode"`
	AccountCount                 int                    `json:"account_count"`
	SelectedAccountCount         int                    `json:"selected_account_count"`
	ChangedAccountCount          int                    `json:"changed_account_count"`
	SetAccountCount              int                    `json:"set_account_count"`
	ClearedAccountCount          int                    `json:"cleared_account_count"`
	UnchangedAccountCount        int                    `json:"unchanged_account_count"`
	PreviousExternalIDConfigured bool                   `json:"previous_external_id_configured"`
	PreviousExternalIDConsistent bool                   `json:"previous_external_id_consistent"`
	TargetExternalIDConfigured   bool                   `json:"target_external_id_configured"`
	TargetExternalIDConsistent   bool                   `json:"target_external_id_consistent"`
	Changes                      []ExternalIDChange     `json:"changes"`
	Output                       string                 `json:"output"`
	PayloadSHA256                string                 `json:"payload_sha256"`
	PlanDigest                   string                 `json:"plan_digest,omitempty"`
	RollbackOutput               string                 `json:"rollback_output,omitempty"`
	RollbackSHA256               string                 `json:"rollback_sha256,omitempty"`
	ResultJournalOutput          string                 `json:"result_journal_output,omitempty"`
	Payload                      ExternalIDPatchPayload `json:"payload"`
}

type ExternalIDChange struct {
	AccountID          string `json:"account_id"`
	AccountName        string `json:"account_name,omitempty"`
	Action             string `json:"action"`
	PreviousConfigured bool   `json:"previous_configured"`
	TargetConfigured   bool   `json:"target_configured"`
	Changed            bool   `json:"changed"`
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
	externalIDFile := strings.TrimSpace(cfg.ExternalIDFile)
	if externalIDFile != "" {
		if externalID != "" || cfg.Clear || len(cfg.AccountIDs) > 0 {
			return nil, fmt.Errorf("--external-id-file cannot be combined with --value, --clear, or --account-id")
		}
	} else if cfg.Clear == (externalID != "") {
		return nil, fmt.Errorf("specify exactly one of an external ID value or clear")
	}

	assignments, err := loadExternalIDAssignments(externalIDFile, setupID)
	if err != nil {
		return nil, err
	}
	if externalIDFile != "" {
		for assignmentSetupID := range assignments {
			if assignmentSetupID != setupID {
				return nil, fmt.Errorf("external ID file contains setup %s but command selected %s", assignmentSetupID, setupID)
			}
		}
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
	seenCurrent := make(map[string]bool, len(infos))
	for _, info := range infos {
		accountID := assumeRoleAccountID(info)
		if accountID == "" {
			return nil, fmt.Errorf("AWS setup %s contains an assumeRoleInfos entry without an account ID", setupID)
		}
		if seenCurrent[accountID] {
			return nil, fmt.Errorf("AWS setup %s contains duplicate account %s", setupID, accountID)
		}
		seenCurrent[accountID] = true
	}
	mode := "all"
	selected := make(map[string]string)
	if externalIDFile != "" {
		mode = "file"
		for accountID, value := range assignments[setupID] {
			selected[accountID] = value
		}
	} else if len(cfg.AccountIDs) > 0 {
		mode = "selected"
		for _, rawAccountID := range cfg.AccountIDs {
			accountID := strings.TrimSpace(rawAccountID)
			if _, err := NewAccountID(accountID); err != nil {
				return nil, fmt.Errorf("invalid AWS account ID %q; expected 12 digits", rawAccountID)
			}
			if _, exists := selected[accountID]; exists {
				return nil, fmt.Errorf("duplicate --account-id %s", accountID)
			}
			selected[accountID] = externalID
		}
	} else {
		for _, info := range infos {
			accountID := assumeRoleAccountID(info)
			selected[accountID] = externalID
		}
	}

	found := make(map[string]bool, len(selected))
	changes := make([]ExternalIDChange, 0, len(selected))
	changedCount := 0
	setCount := 0
	clearedCount := 0
	for i := range infos {
		accountID := assumeRoleAccountID(infos[i])
		target, ok := selected[accountID]
		if !ok {
			continue
		}
		found[accountID] = true
		previous := strings.TrimSpace(infos[i].ExternalID)
		changed := previous != target
		if changed {
			changedCount++
		}
		action := "set"
		if target == "" {
			action = "clear"
			clearedCount++
		} else {
			setCount++
		}
		changes = append(changes, ExternalIDChange{
			AccountID:          accountID,
			AccountName:        infos[i].AccountName,
			Action:             action,
			PreviousConfigured: previous != "",
			TargetConfigured:   target != "",
			Changed:            changed,
		})
		infos[i].ExternalID = target
	}
	missing := make([]string, 0)
	for accountID := range selected {
		if !found[accountID] {
			missing = append(missing, accountID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("AWS setup %s does not contain selected account(s): %s", setupID, strings.Join(missing, ", "))
	}
	targetConfigured, targetConsistent := externalIDState(infos)
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
		Mode:                         mode,
		AccountCount:                 len(infos),
		SelectedAccountCount:         len(selected),
		ChangedAccountCount:          changedCount,
		SetAccountCount:              setCount,
		ClearedAccountCount:          clearedCount,
		UnchangedAccountCount:        len(selected) - changedCount,
		PreviousExternalIDConfigured: previousConfigured,
		PreviousExternalIDConsistent: previousConsistent,
		TargetExternalIDConfigured:   targetConfigured,
		TargetExternalIDConsistent:   targetConsistent,
		Changes:                      changes,
		Output:                       output,
		PayloadSHA256:                sha,
		Payload:                      payload,
	}
	if !cfg.Apply || changedCount == 0 {
		return summary, nil
	}

	rollbackPayloads, err := buildRollbackPayloads(accounts, []string{setupID})
	if err != nil {
		return nil, err
	}
	fullTarget := clonePatchPayload(rollbackPayloads[setupID])
	fullTarget.AssumeRoleInfos = append([]api.AssumeRoleInfo(nil), infos...)
	typedSetupID, err := NewSetupID(setupID)
	if err != nil {
		return nil, err
	}
	changeSet, err := classifyPatchPayload(account, typedSetupID, fullTarget)
	if err != nil {
		return nil, fmt.Errorf("classify External ID change for setup %s: %w", setupID, err)
	}
	intent, err := newPayloadApplyIntent(
		networkID,
		output,
		InventorySnapshot{
			Source:           "external-id",
			SelectedSetupIDs: []SetupID{typedSetupID},
			Completeness:     InventoryCompletenessUnknown,
		},
		ReconcilePolicy{
			Kind:                 ExplicitOperations,
			PlanningInstant:      time.Now().UTC(),
			OrganizationEvidence: AllowMissingOrganizationEvidence,
		},
		accounts,
		auditPayloads{setupID: fullTarget},
		map[string]ChangeSet{setupID: changeSet},
	)
	if err != nil {
		return nil, err
	}
	summary.PlanDigest = intent.Digest()
	if cfg.ConfirmApply != nil {
		if err := cfg.ConfirmApply(intent.Digest()); err != nil {
			return summary, err
		}
	}
	actor := strings.TrimSpace(cfg.AuthorizationActor)
	if actor == "" {
		actor = "external-id caller"
	}
	applyResult, applyErr := GuardAndApply(ctx, client, intent, ApplyAuthorization{
		PlanDigest: intent.Digest(),
		Actor:      actor,
		Approved:   true,
		Unattended: cfg.Unattended,
	})
	summary.Patched = applyResult.PatchedCount > 0
	summary.RollbackOutput = applyResult.RollbackOutput
	summary.RollbackSHA256 = applyResult.RollbackSHA256
	summary.ResultJournalOutput = applyResult.JournalOutput
	if applyErr != nil {
		if applyResult.JournalOutput != "" {
			return summary, fmt.Errorf("%w; apply result journal: %s", applyErr, applyResult.JournalOutput)
		}
		return summary, applyErr
	}
	return summary, nil
}

func assumeRoleAccountID(info api.AssumeRoleInfo) string {
	if accountID := strings.TrimSpace(info.AccountID); accountID != "" {
		return accountID
	}
	return accountIDFromRoleArn(info.RoleArn)
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
