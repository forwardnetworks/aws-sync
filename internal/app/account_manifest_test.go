package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestSyncAWSAccountManifestWarnsWhenManifestMatchesNQEButNotConfiguredMembership(t *testing.T) {
	server := newManifestSafeguardTestServer(t)
	defer server.Close()

	summary, err := SyncAWSAccountManifest(context.Background(), Config{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		SetupIDs:  []string{"setup-a"},
		APIPrefix: "/api",
		Output:    filepath.Join(t.TempDir(), "plan.json"),
	}, manifestSafeguardAccounts())
	if err != nil {
		t.Fatalf("SyncAWSAccountManifest() error = %v", err)
	}
	if len(summary.SafetyWarnings) != 1 || summary.SafetyWarnings[0].Code != "manifest_matches_nqe_observation" {
		t.Fatalf("safety warnings = %#v", summary.SafetyWarnings)
	}
	if !strings.Contains(summary.SafetyWarnings[0].Message, "legitimate manifest can coincidentally match NQE") {
		t.Fatalf("warning does not explain false-positive behavior: %q", summary.SafetyWarnings[0].Message)
	}
}

func TestSyncAWSAccountManifestSurfacesHighRemovalFraction(t *testing.T) {
	server := newManifestSafeguardTestServer(t)
	defer server.Close()

	summary, err := SyncAWSAccountManifest(context.Background(), Config{
		Host:              server.URL,
		Username:          "user",
		Password:          "pass",
		NetworkID:         "network-1",
		SetupIDs:          []string{"setup-a"},
		APIPrefix:         "/api",
		Output:            filepath.Join(t.TempDir(), "plan.json"),
		MaxRemovals:       5,
		MaxRemovalPercent: 100,
	}, manifestSafeguardAccounts())
	if err != nil {
		t.Fatalf("SyncAWSAccountManifest() error = %v", err)
	}
	if len(summary.RemovalImpacts) != 1 {
		t.Fatalf("removal impacts = %#v", summary.RemovalImpacts)
	}
	impact := summary.RemovalImpacts[0]
	if impact.RemovedCount != 3 || impact.ConfiguredCount != 5 || impact.RemovalPercent != 60 ||
		impact.Message != "This removes 3 of 5 accounts (60.00%) from setup setup-a." {
		t.Fatalf("removal impact = %#v", impact)
	}
}

func newManifestSafeguardTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"Cloud Setup ID":"setup-a","Cloud Account ID":"111111111111","Cloud Account Name":"one","Collected?":true},
				{"Cloud Setup ID":"setup-a","Cloud Account ID":"222222222222","Cloud Account Name":"two","Collected?":true}
			]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			infos := make([]api.AssumeRoleInfo, 0, 5)
			for _, accountID := range []string{
				"111111111111",
				"222222222222",
				"333333333333",
				"444444444444",
				"555555555555",
			} {
				infos = append(infos, api.AssumeRoleInfo{
					AccountID: accountID,
					RoleArn:   "arn:aws:iam::" + accountID + ":role/ForwardRole",
					Enabled:   true,
				})
			}
			_ = json.NewEncoder(w).Encode([]api.CloudAccount{{
				Type:            "AWS",
				Name:            "setup-a",
				AssumeRoleInfos: infos,
			}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func manifestSafeguardAccounts() []AWSOrganizationAccount {
	return []AWSOrganizationAccount{
		{ID: "111111111111", Name: "one"},
		{ID: "222222222222", Name: "two"},
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
	var patchedPayload api.PatchPayload
	current := api.CloudAccount{
		Type: "AWS",
		Name: "gov-prod",
		Regions: map[string]api.RegionMeta{
			"us-gov-west-1": {TestInstant: 1},
		},
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111111111111", AccountName: "keep", RoleArn: "arn:aws-us-gov:iam::111111111111:role/ForwardRole", Enabled: true},
			{AccountID: "222222222222", AccountName: "remove", RoleArn: "arn:aws-us-gov:iam::222222222222:role/ForwardRole", Enabled: true},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_ = json.NewEncoder(w).Encode([]api.CloudAccount{current})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/gov-prod":
			if err := json.NewDecoder(r.Body).Decode(&patchedPayload); err != nil {
				t.Errorf("decode PATCH payload: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			patchCount++
			current = testCloudAccountFromPatchPayload(patchedPayload)
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
	approved.MaxRemovals = 1
	approved.MaxRemovalPercent = 50
	approved.Output = filepath.Join(t.TempDir(), "approved.json")
	if _, err := SyncAWSAccountManifest(context.Background(), approved, accounts); err != nil {
		t.Fatalf("approved apply error = %v", err)
	}
	if patchCount != 1 {
		t.Fatalf("approved apply patch count = %d, want 1", patchCount)
	}
	if len(patchedPayload.AssumeRoleInfos) != 1 || patchedPayload.AssumeRoleInfos[0].AccountID != "111111111111" {
		t.Fatalf("approved manifest removal PATCH = %#v; want only reviewed account 111111111111", patchedPayload.AssumeRoleInfos)
	}
}

func TestApprovalDigestStableAcrossIndependentPlanningProcesses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{
          "type":"AWS",
          "name":"setup-a",
          "regions":{"us-east-1":{"testInstant":0}},
          "assumeRoleInfos":[{
            "accountId":"111111111111",
            "accountName":"keep",
            "roleArn":"arn:aws:iam::111111111111:role/ForwardRole",
            "enabled":true
          }]
        }]`))
	}))
	defer server.Close()

	runPlanningProcess := func(name string, instant time.Time) Summary {
		t.Helper()
		dir := t.TempDir()
		resultPath := filepath.Join(dir, "summary.json")
		cmd := exec.Command(os.Args[0], "-test.run=^TestApprovalDigestPlanningProcess$")
		cmd.Env = append(os.Environ(),
			"AWSSYNC_PLAN_DIGEST_CHILD=1",
			"AWSSYNC_PLAN_DIGEST_HOST="+server.URL,
			"AWSSYNC_PLAN_DIGEST_INSTANT="+instant.Format(time.RFC3339Nano),
			"AWSSYNC_PLAN_DIGEST_OUTPUT="+filepath.Join(dir, name+"-payload.json"),
			"AWSSYNC_PLAN_DIGEST_RESULT="+resultPath,
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("planning process %s failed: %v\n%s", name, err, output)
		}
		data, err := os.ReadFile(resultPath)
		if err != nil {
			t.Fatalf("read planning result %s: %v", name, err)
		}
		var summary Summary
		if err := json.Unmarshal(data, &summary); err != nil {
			t.Fatalf("decode planning result %s: %v", name, err)
		}
		return summary
	}

	first := runPlanningProcess("first", time.Unix(100, 0).UTC())
	second := runPlanningProcess("second", time.Unix(200, 0).UTC())
	if first.PlanDigest == "" || first.PlanDigest != second.PlanDigest {
		t.Fatalf("approval digests differ across independent planning processes: %q != %q", first.PlanDigest, second.PlanDigest)
	}
	if first.PayloadSHA256 == second.PayloadSHA256 {
		t.Fatalf("test setup did not produce distinct exact payloads: both hashes are %q", first.PayloadSHA256)
	}
}

func TestApprovalDigestPlanningProcess(t *testing.T) {
	if os.Getenv("AWSSYNC_PLAN_DIGEST_CHILD") != "1" {
		return
	}
	planningInstant, err := time.Parse(time.RFC3339Nano, os.Getenv("AWSSYNC_PLAN_DIGEST_INSTANT"))
	if err != nil {
		t.Fatalf("parse planning instant: %v", err)
	}
	summary, err := SyncAWSAccountManifest(context.Background(), Config{
		Host:      os.Getenv("AWSSYNC_PLAN_DIGEST_HOST"),
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		SetupIDs:  []string{"setup-a"},
		APIPrefix: "/api",
		Output:    os.Getenv("AWSSYNC_PLAN_DIGEST_OUTPUT"),
		Policy:    NewAuthoritativeManifestReconcilePolicy(planningInstant),
	}, []AWSOrganizationAccount{
		{ID: "111111111111", Name: "keep"},
		{ID: "222222222222", Name: "add"},
	})
	if err != nil {
		t.Fatalf("plan account manifest: %v", err)
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("encode planning summary: %v", err)
	}
	if err := os.WriteFile(os.Getenv("AWSSYNC_PLAN_DIGEST_RESULT"), data, 0o600); err != nil {
		t.Fatalf("write planning summary: %v", err)
	}
}
