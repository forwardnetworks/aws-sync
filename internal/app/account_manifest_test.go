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

func TestLoadAWSAccountManifestValidatesAndNormalizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte(`[
  {"id":"111111111111","name":"security"},
  {"id":"222222222222"}
]`), 0o600); err != nil {
		t.Fatal(err)
	}

	accounts, err := LoadAWSAccountManifest(path)
	if err != nil {
		t.Fatalf("LoadAWSAccountManifest() error = %v", err)
	}
	if len(accounts) != 2 || accounts[0].Name != "security" || accounts[1].Name != "222222222222" {
		t.Fatalf("unexpected accounts: %#v", accounts)
	}
}

func TestLoadAWSAccountManifestRejectsInvalidAndDuplicateIDs(t *testing.T) {
	for name, contents := range map[string]string{
		"invalid":   `[{"id":"123"}]`,
		"duplicate": `[{"id":"111111111111"},{"id":"111111111111"}]`,
		"unknown":   `[{"id":"111111111111","email":"private@example.gov"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "accounts.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAWSAccountManifest(path); err == nil {
				t.Fatal("expected manifest validation error")
			}
		})
	}
}

func TestRunAWSAccountManifestBuildsGovCloudRoleARNs(t *testing.T) {
	output := filepath.Join(t.TempDir(), "payload.json")
	summary, err := RunAWSAccountManifest(context.Background(), AWSOrganizationConfig{
		SetupIDs:       []string{"gov-prod"},
		RoleName:       "ForwardReadOnlyAccess",
		ExternalID:     "customer-value",
		Regions:        []string{"us-gov-west-1"},
		Partition:      "aws-us-gov",
		CredentialMode: CredentialModeInstanceProfile,
		Output:         output,
		IncludeManual:  true,
	}, []AWSOrganizationAccount{{ID: "111111111111", Name: "security"}})
	if err != nil {
		t.Fatalf("RunAWSAccountManifest() error = %v", err)
	}
	if summary.Source != "account_manifest" || summary.PostedSetupCount != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if !strings.Contains(summary.PlannedSetups[0].OrganizationDiscoveryMessage, "Organizations was not queried") {
		t.Fatalf("unexpected discovery message: %#v", summary.PlannedSetups[0])
	}

	var payload api.CreateAWSPayload
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	want := "arn:aws-us-gov:iam::111111111111:role/ForwardReadOnlyAccess"
	if got := payload.AssumeRoleInfos[0].RoleArn; got != want {
		t.Fatalf("role ARN = %q, want %q", got, want)
	}
	if payload.UseForwardAccountToAssumeRole == nil || *payload.UseForwardAccountToAssumeRole {
		t.Fatalf("expected collector instance-profile mode: %#v", payload)
	}
	if payload.Username != "" || payload.Password != "" {
		t.Fatalf("instance-profile payload must not contain static credentials: %#v", payload)
	}
}

func TestRunAWSAccountManifestRejectsPartitionRegionMismatch(t *testing.T) {
	_, err := RunAWSAccountManifest(context.Background(), AWSOrganizationConfig{
		SetupIDs:  []string{"gov-prod"},
		RoleName:  "ForwardReadOnlyAccess",
		Regions:   []string{"us-east-1"},
		Partition: "aws-us-gov",
		Output:    filepath.Join(t.TempDir(), "payload.json"),
	}, []AWSOrganizationAccount{{ID: "111111111111"}})
	if err == nil || !strings.Contains(err.Error(), "does not belong to partition") {
		t.Fatalf("expected partition mismatch, got %v", err)
	}
}

func TestSyncAWSAccountManifestDryRunReportsRemovalAndApplyRequiresApproval(t *testing.T) {
	patchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"gov-prod","regions":{"us-gov-west-1":{"testInstant":1}},"assumeRoleInfos":[
              {"accountId":"111111111111","accountName":"keep","roleArn":"arn:aws-us-gov:iam::111111111111:role/ForwardRole","enabled":true},
              {"accountId":"222222222222","accountName":"remove","roleArn":"arn:aws-us-gov:iam::222222222222:role/ForwardRole","enabled":true}
            ]}]`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/gov-prod":
			patchCount++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	accounts := []AWSOrganizationAccount{{ID: "111111111111", Name: "keep"}}
	base := Config{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		SetupIDs:  []string{"gov-prod"},
		APIPrefix: "/api",
		Output:    filepath.Join(t.TempDir(), "plan.json"),
		Apply:     false,
	}
	summary, err := SyncAWSAccountManifest(context.Background(), base, accounts)
	if err != nil {
		t.Fatalf("dry run error = %v", err)
	}
	if summary.Source != "account_manifest" || len(summary.PlannedSetups[0].RemovedAccounts) != 1 {
		t.Fatalf("expected one visible manifest removal: %#v", summary)
	}
	if got := summary.PlannedSetups[0].RemovedAccounts[0].AccountID; got != "222222222222" {
		t.Fatalf("removed account = %q", got)
	}
	if patchCount != 0 {
		t.Fatalf("dry run unexpectedly patched %d setup(s)", patchCount)
	}

	blocked := base
	blocked.Apply = true
	blocked.Output = filepath.Join(t.TempDir(), "blocked.json")
	if _, err := SyncAWSAccountManifest(context.Background(), blocked, accounts); err == nil || !strings.Contains(err.Error(), "--allow-removals") {
		t.Fatalf("expected removal approval error, got %v", err)
	}
	if patchCount != 0 {
		t.Fatalf("blocked apply unexpectedly patched %d setup(s)", patchCount)
	}

	approved := blocked
	approved.AllowRemovals = true
	approved.Output = filepath.Join(t.TempDir(), "approved.json")
	if _, err := SyncAWSAccountManifest(context.Background(), approved, accounts); err != nil {
		t.Fatalf("approved apply error = %v", err)
	}
	if patchCount != 1 {
		t.Fatalf("approved apply patch count = %d, want 1", patchCount)
	}
}
