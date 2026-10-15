package app

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

// ExternalIDStatusConfig selects what to report. It is read-only: nothing here
// can change Forward. ExternalID, Clear and ExternalIDFile describe the state
// the operator expects (the same inputs `external-id` takes), so the report can
// say which accounts already match without ever showing a value.
type ExternalIDStatusConfig struct {
	Host           string
	Username       string
	Password       string
	NetworkID      string
	SetupID        string
	AccountIDs     []string
	ExternalID     string
	Clear          bool
	ExternalIDFile string
	Output         string
	APIPrefix      string
	Insecure       bool
	Timeout        time.Duration
}

// ExternalIDStatusAccount is one account's External ID state. The value itself
// is never included.
type ExternalIDStatusAccount struct {
	AccountID          string `json:"account_id"`
	AccountName        string `json:"account_name,omitempty"`
	Enabled            bool   `json:"enabled"`
	ExternalIDSet      bool   `json:"external_id_set"`
	Expected           string `json:"expected,omitempty"`
	InSync             *bool  `json:"in_sync,omitempty"`
	CollectionErrorSet bool   `json:"collection_error"`
}

type ExternalIDStatusSummary struct {
	Host          string                    `json:"host"`
	NetworkID     string                    `json:"network_id"`
	SetupID       string                    `json:"setup_id"`
	Compared      bool                      `json:"compared"`
	AccountCount  int                       `json:"account_count"`
	ListedCount   int                       `json:"listed_count"`
	SetCount      int                       `json:"set_count"`
	UnsetCount    int                       `json:"unset_count"`
	ComparedCount int                       `json:"compared_count"`
	InSyncCount   int                       `json:"in_sync_count"`
	OutOfSync     []string                  `json:"out_of_sync_account_ids"`
	AllInSync     bool                      `json:"all_in_sync"`
	Uniform       bool                      `json:"all_accounts_hold_the_same_state"`
	Accounts      []ExternalIDStatusAccount `json:"accounts"`
	Output        string                    `json:"output,omitempty"`
	ValuesShown   bool                      `json:"values_shown"`
	ComparisonMsg string                    `json:"comparison,omitempty"`
}

// ReportExternalIDStatus reads a setup and reports, per account, whether an
// External ID is set. With ExternalID, Clear or ExternalIDFile it also reports
// whether each selected account already matches that expectation. It never
// prints, returns or writes a value.
func ReportExternalIDStatus(ctx context.Context, cfg ExternalIDStatusConfig) (*ExternalIDStatusSummary, error) {
	setupID := strings.TrimSpace(cfg.SetupID)
	if setupID == "" {
		return nil, fmt.Errorf("setup ID is required")
	}
	value := strings.TrimSpace(cfg.ExternalID)
	file := strings.TrimSpace(cfg.ExternalIDFile)
	compare := value != "" || cfg.Clear || file != ""
	switch {
	case file != "" && (value != "" || cfg.Clear):
		return nil, fmt.Errorf("--external-id-file cannot be combined with --value or --clear")
	case value != "" && cfg.Clear:
		return nil, fmt.Errorf("specify at most one of an external ID value or clear")
	case file != "" && len(cfg.AccountIDs) > 0:
		return nil, fmt.Errorf("--external-id-file cannot be combined with --account-id")
	}

	// expected maps account -> expected value ("" means expected unset).
	expected := map[string]string{}
	if file != "" {
		assignments, err := loadExternalIDAssignments(file, setupID)
		if err != nil {
			return nil, err
		}
		for assignmentSetupID := range assignments {
			if assignmentSetupID != setupID {
				return nil, fmt.Errorf("external ID file has rows for a setup other than the selected setup %s", setupID)
			}
		}
		for accountID, v := range assignments[setupID] {
			expected[accountID] = v
		}
	}

	client, err := api.NewClient(cfg.Host, cfg.APIPrefix, cfg.Username, cfg.Password, cfg.Insecure, cfg.Timeout)
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
		return nil, fmt.Errorf("AWS setup %s has no assumeRoleInfos to report on", setupID)
	}

	filter := map[string]bool{}
	for _, raw := range cfg.AccountIDs {
		accountID := strings.TrimSpace(raw)
		if _, err := NewAccountID(accountID); err != nil {
			return nil, fmt.Errorf("an --account-id value is not a 12-digit AWS account ID (the value is not shown)")
		}
		if filter[accountID] {
			return nil, fmt.Errorf("duplicate --account-id %s", accountID)
		}
		filter[accountID] = true
	}

	present := map[string]bool{}
	rows := make([]ExternalIDStatusAccount, 0, len(account.AssumeRoleInfos))
	for _, info := range account.AssumeRoleInfos {
		accountID := assumeRoleAccountID(info)
		if accountID == "" {
			return nil, fmt.Errorf("AWS setup %s contains an assumeRoleInfos entry without an account ID", setupID)
		}
		if present[accountID] {
			return nil, fmt.Errorf("AWS setup %s contains duplicate account %s", setupID, accountID)
		}
		present[accountID] = true
	}
	missing := []string{}
	for accountID := range filter {
		if !present[accountID] {
			missing = append(missing, accountID)
		}
	}
	for accountID := range expected {
		if !present[accountID] {
			missing = append(missing, accountID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("AWS setup %s does not contain selected account(s): %s", setupID, strings.Join(missing, ", "))
	}

	outOfSync := []string{}
	set, unset, inSync := 0, 0, 0
	for _, info := range account.AssumeRoleInfos {
		accountID := assumeRoleAccountID(info)
		current := strings.TrimSpace(info.ExternalID)
		if current != "" {
			set++
		} else {
			unset++
		}
		if len(filter) > 0 && !filter[accountID] {
			continue
		}
		row := ExternalIDStatusAccount{
			AccountID:          accountID,
			AccountName:        info.AccountName,
			Enabled:            info.Enabled,
			ExternalIDSet:      current != "",
			CollectionErrorSet: strings.TrimSpace(info.ErrorMsg) != "",
		}
		if compare {
			want, listed := "", true
			switch {
			case file != "":
				want, listed = expected[accountID]
			default:
				want = value
			}
			if listed {
				match := current == want
				row.InSync = &match
				if want == "" {
					row.Expected = "unset"
				} else {
					row.Expected = "set"
				}
				if match {
					inSync++
				} else {
					outOfSync = append(outOfSync, accountID)
				}
			} else {
				row.Expected = "not in file"
			}
		}
		rows = append(rows, row)
	}
	sort.Strings(outOfSync)
	_, uniform := externalIDState(account.AssumeRoleInfos)

	summary := &ExternalIDStatusSummary{
		OutOfSync:    []string{},
		Host:         cfg.Host,
		NetworkID:    networkID,
		SetupID:      setupID,
		Compared:     compare,
		AccountCount: len(account.AssumeRoleInfos),
		ListedCount:  len(rows),
		SetCount:     set,
		UnsetCount:   unset,
		Uniform:      uniform,
		Accounts:     rows,
	}
	if compare {
		summary.ComparedCount = inSync + len(outOfSync)
		summary.InSyncCount = inSync
		summary.OutOfSync = outOfSync
		summary.AllInSync = len(outOfSync) == 0
		summary.ComparisonMsg = "compared with the value or file you gave; values are never shown, only whether each account matches"
	}
	if out := strings.TrimSpace(cfg.Output); out != "" {
		data, err := externalIDStatusCSV(setupID, rows, compare)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic0600(out, data); err != nil {
			return nil, fmt.Errorf("write status CSV: %w", err)
		}
		summary.Output = out
	}
	return summary, nil
}

func externalIDStatusCSV(setupID string, rows []ExternalIDStatusAccount, compare bool) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	header := []string{"setup_id", "account_id", "account_name", "enabled", "external_id_set"}
	if compare {
		header = append(header, "expected", "in_sync")
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	for _, row := range rows {
		record := []string{csvSafe(setupID), row.AccountID, csvSafe(row.AccountName), fmt.Sprint(row.Enabled), fmt.Sprint(row.ExternalIDSet)}
		if compare {
			inSync := ""
			if row.InSync != nil {
				inSync = fmt.Sprint(*row.InSync)
			}
			record = append(record, row.Expected, inSync)
		}
		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

// csvSafe stops a spreadsheet from running an account name as a formula.
func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}
