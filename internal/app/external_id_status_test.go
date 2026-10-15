package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

const statusSecret = "TOP-SECRET-VALUE-12345"

// statusFixture serves one AWS setup and fails the test on anything but a GET.
func statusFixture(t *testing.T) ExternalIDStatusConfig {
	t.Helper()
	setup := api.CloudAccount{
		Type: "AWS",
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111111111111", AccountName: "=cmd-name", RoleArn: "arn:aws:iam::111111111111:role/R", Enabled: true, ExternalID: statusSecret},
			{AccountID: "222222222222", AccountName: "other", RoleArn: "arn:aws:iam::222222222222:role/R", Enabled: true, ExternalID: "different-value"},
			{AccountID: "333333333333", AccountName: "unset", RoleArn: "arn:aws:iam::333333333333:role/R", Enabled: false, ErrorMsg: "boom"},
		},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("status must be read-only, got %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]api.CloudAccount{setup})
	}))
	t.Cleanup(server.Close)
	return ExternalIDStatusConfig{
		Host: server.URL, Username: "alice", Password: "secret", NetworkID: "network-1",
		SetupID: "setup-a", APIPrefix: "/api", Insecure: true,
	}
}

func TestExternalIDStatusNeverRevealsAValueAndOnlyReads(t *testing.T) {
	cfg := statusFixture(t)
	cfg.ExternalID = statusSecret
	cfg.Output = filepath.Join(t.TempDir(), "status.csv")
	summary, err := ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("ReportExternalIDStatus() error = %v", err)
	}
	encoded, _ := json.Marshal(summary)
	csv, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	for _, text := range []string{string(encoded), string(csv)} {
		if strings.Contains(text, statusSecret) || strings.Contains(text, "different-value") {
			t.Fatalf("an External ID value leaked into the report: %s", text)
		}
	}
	if info, err := os.Stat(cfg.Output); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("CSV mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if !strings.Contains(string(csv), "'=cmd-name") {
		t.Fatalf("an account name starting with = must not be written as a spreadsheet formula: %s", csv)
	}
}

func TestExternalIDStatusCountsAndComparison(t *testing.T) {
	cfg := statusFixture(t)

	// No expectation: just who has a value.
	summary, err := ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if summary.AccountCount != 3 || summary.SetCount != 2 || summary.UnsetCount != 1 || summary.Compared {
		t.Fatalf("unexpected plain summary: %+v", summary)
	}

	// --value: only the account holding exactly that value matches.
	cfg.ExternalID = statusSecret
	summary, err = ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !summary.Compared || summary.AllInSync || summary.InSyncCount != 1 ||
		strings.Join(summary.OutOfSync, ",") != "222222222222,333333333333" {
		t.Fatalf("--value comparison wrong: %+v", summary)
	}

	// --account-id limits both the listing and the comparison.
	cfg.AccountIDs = []string{"111111111111"}
	summary, err = ReportExternalIDStatus(context.Background(), cfg)
	if err != nil || summary.ListedCount != 1 || !summary.AllInSync {
		t.Fatalf("--account-id comparison wrong: %+v, %v", summary, err)
	}

	// --clear: only the unset account is in sync.
	cfg.AccountIDs, cfg.ExternalID, cfg.Clear = nil, "", true
	summary, err = ReportExternalIDStatus(context.Background(), cfg)
	if err != nil || summary.InSyncCount != 1 || strings.Join(summary.OutOfSync, ",") != "111111111111,222222222222" {
		t.Fatalf("--clear comparison wrong: %+v, %v", summary, err)
	}
}

func TestExternalIDStatusFileComparesOnlyListedAccounts(t *testing.T) {
	cfg := statusFixture(t)
	cfg.ExternalIDFile = filepath.Join(t.TempDir(), "ids.csv")
	content := "setup_id,account_id,action,external_id\n" +
		"setup-a,111111111111,set," + statusSecret + "\n" +
		"setup-a,333333333333,clear,\n"
	if err := os.WriteFile(cfg.ExternalIDFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !summary.AllInSync || summary.InSyncCount != 2 {
		t.Fatalf("both listed accounts match; the unlisted one must not count as a mismatch: %+v", summary)
	}
	for _, account := range summary.Accounts {
		if account.AccountID == "222222222222" && (account.InSync != nil || account.Expected != "not in file") {
			t.Fatalf("an account missing from the file must not be compared: %+v", account)
		}
	}
}

func TestExternalIDStatusRejectsBadSelections(t *testing.T) {
	cfg := statusFixture(t)
	cfg.AccountIDs = []string{"999999999999"}
	if _, err := ReportExternalIDStatus(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("unknown account error = %v", err)
	}
	cfg.AccountIDs = []string{"not-an-id"}
	if _, err := ReportExternalIDStatus(context.Background(), cfg); err == nil {
		t.Fatal("a malformed account ID must be rejected")
	}
	cfg = statusFixture(t)
	cfg.ExternalID, cfg.Clear = "x", true
	if _, err := ReportExternalIDStatus(context.Background(), cfg); err == nil {
		t.Fatal("--value with --clear must be rejected")
	}
}

// An operator who swaps CSV columns, or pastes a value into the wrong flag,
// must not see the External ID echoed back in an error.
func TestMalformedInputErrorsNeverEchoAValue(t *testing.T) {
	const secret = "MySecretExternalID9"
	files := map[string]string{
		"value in account column": "setup_id,account_id,action,external_id\nsetup-a," + secret + ",set,111111111111\n",
		"value in action column":  "setup_id,account_id,action,external_id\nsetup-a,111111111111," + secret + ",set\n",
		"value in setup column":   "setup_id,account_id,action,external_id\n" + secret + ",111111111111,set,x\n",
		"value in two columns":    "setup_id,account_id,action,external_id\nsetup-a,111111111111,set,x\nsetup-a,111111111111,set," + secret + "\n",
		"other setup rows":        "setup_id,account_id,action,external_id\n" + secret + "-setup,111111111111,set,x\n",
	}
	for name, content := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ids.csv")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := statusFixture(t)
			cfg.ExternalIDFile = path
			if _, err := ReportExternalIDStatus(context.Background(), cfg); err != nil && strings.Contains(err.Error(), secret) {
				t.Fatalf("external-id-status error echoed the value: %v", err)
			}
			change := ExternalIDConfig{
				Host: cfg.Host, Username: cfg.Username, Password: cfg.Password, NetworkID: cfg.NetworkID,
				SetupID: cfg.SetupID, APIPrefix: "/api", Insecure: true, ExternalIDFile: path,
				Output: filepath.Join(t.TempDir(), "plan.json"),
			}
			if _, err := ChangeExternalID(context.Background(), change); err != nil && strings.Contains(err.Error(), secret) {
				t.Fatalf("external-id error echoed the value: %v", err)
			}
		})
	}
	// A value pasted into --account-id.
	cfg := statusFixture(t)
	cfg.AccountIDs = []string{secret}
	if _, err := ReportExternalIDStatus(context.Background(), cfg); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("--account-id error = %v; want a refusal that does not echo the value", err)
	}
	change := ExternalIDConfig{
		Host: cfg.Host, Username: cfg.Username, Password: cfg.Password, NetworkID: cfg.NetworkID,
		SetupID: cfg.SetupID, APIPrefix: "/api", Insecure: true, AccountIDs: []string{secret}, ExternalID: "x",
		Output: filepath.Join(t.TempDir(), "plan.json"),
	}
	if _, err := ChangeExternalID(context.Background(), change); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("external-id --account-id error = %v; want a refusal that does not echo the value", err)
	}
}

func TestExternalIDStatusFilterCountsAreScopedAndLabelled(t *testing.T) {
	cfg := statusFixture(t)
	cfg.AccountIDs = []string{"222222222222"}
	cfg.ExternalID = "different-value"
	summary, err := ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// Whole-setup counts stay whole-setup; the comparison covers only what was listed.
	if summary.AccountCount != 3 || summary.SetCount != 2 || summary.UnsetCount != 1 {
		t.Fatalf("whole-setup counts changed under a filter: %+v", summary)
	}
	if summary.ListedCount != 1 || summary.ComparedCount != 1 || summary.InSyncCount != 1 || !summary.AllInSync {
		t.Fatalf("comparison must cover only the listed account: %+v", summary)
	}
	// A value with surrounding whitespace compares as the trimmed value, like external-id.
	cfg.ExternalID = "  different-value  "
	if summary, err = ReportExternalIDStatus(context.Background(), cfg); err != nil || !summary.AllInSync {
		t.Fatalf("whitespace around the expected value must not matter: %+v, %v", summary, err)
	}
	// A mismatch must stay visible in JSON as false/0, not vanish.
	cfg.ExternalID = "nope"
	summary, err = ReportExternalIDStatus(context.Background(), cfg)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	encoded, _ := json.Marshal(summary)
	for _, key := range []string{`"all_in_sync":false`, `"in_sync_count":0`, `"compared_count":1`} {
		if !strings.Contains(string(encoded), key) {
			t.Fatalf("JSON lost %s on a mismatch: %s", key, encoded)
		}
	}
}
