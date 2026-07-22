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
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestBuildPlanGroupsMultipleSetups(t *testing.T) {
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a"},
		{"Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a-dup"},
		{"Setup ID": "setup-b", "Cloud Account ID": "222", "Cloud Account Name": "acct-b"},
	}
	cloudAccounts := []api.CloudAccount{
		{
			Name:            "setup-a",
			ProxyServerID:   "proxy-1",
			Regions:         map[string]api.RegionMeta{"us-east-1": {TestInstant: 123}},
			AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111:role/ForwardRole", ExternalID: "Org:55", Enabled: true}},
		},
		{
			Name:            "setup-b",
			Regions:         map[string]api.RegionMeta{"us-west-2": {TestInstant: 456}},
			AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::222:role/ForwardRole", Enabled: true}},
		},
	}

	plan, err := buildPlan(items, cloudAccounts, "custom-query", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if len(plan.Setups) != 2 {
		t.Fatalf("expected 2 setups, got %d", len(plan.Setups))
	}
	if len(plan.Payloads["setup-a"].AssumeRoleInfos) != 1 {
		t.Fatalf("expected deduped accounts for setup-a, got %#v", plan.Payloads["setup-a"].AssumeRoleInfos)
	}
	if plan.Payloads["setup-a"].ProxyServerID != "proxy-1" {
		t.Fatalf("unexpected proxy server id: %#v", plan.Payloads["setup-a"])
	}
	if len(plan.Payloads["setup-a"].RegionToProxyServerID) != 0 {
		t.Fatalf("unexpected region proxy map: %#v", plan.Payloads["setup-a"])
	}
	if plan.Payloads["setup-a"].AssumeRoleInfos[0].ExternalID != "Org:55" {
		t.Fatalf("unexpected external id: %#v", plan.Payloads["setup-a"].AssumeRoleInfos[0])
	}
	if !plan.Setups[0].ExternalIDConfigured {
		t.Fatalf("expected setup-a to report external id configured: %#v", plan.Setups[0])
	}
	if len(plan.Setups[0].AddedAccounts) != 0 || len(plan.Setups[0].RemovedAccounts) != 0 {
		t.Fatalf("expected no account diff: %#v", plan.Setups[0])
	}
}

func TestRunAWSOrganizationsWithoutForwardWritesManualAndFullPayloads(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "payload.json")
	manual := filepath.Join(dir, "fwd_accounts_data.json")
	source := AWSOrganizationSource{
		OrganizationID:      "o-example",
		ManagementAccountID: "111111111111",
		Accounts: []AWSOrganizationAccount{
			{ID: "111111111111", Name: "management", ParentIDs: []string{"r-root"}},
			{ID: "222222222222", Name: "app", ParentIDs: []string{"ou-root-apps"}},
		},
	}

	summary, err := RunAWSOrganizations(context.Background(), AWSOrganizationConfig{
		SetupIDs:      []string{"aws-prod"},
		RoleName:      "ForwardRole",
		ExternalID:    "Org:123",
		Regions:       []string{"us-east-1", "us-west-2"},
		Output:        output,
		ManualOutput:  manual,
		IncludeManual: true,
	}, source)
	if err != nil {
		t.Fatalf("RunAWSOrganizations() error = %v", err)
	}
	if summary.Source != "aws_organizations" || summary.AWSOrganizationID != "o-example" {
		t.Fatalf("unexpected summary source fields: %#v", summary)
	}
	if summary.Output != output || summary.ManualOutput != manual {
		t.Fatalf("unexpected output paths: %#v", summary)
	}
	if summary.FetchedItemCount != 2 || summary.PlannedSetupCount != 1 {
		t.Fatalf("unexpected summary counts: %#v", summary)
	}
	if !summary.CreatePayloadReady || summary.CredentialMode != CredentialModeForwardRole {
		t.Fatalf("unexpected create payload status: %#v", summary)
	}

	var payload api.CreateAWSPayload
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if payload.Type != "AWS" || payload.Name != "aws-prod" || !payload.Collect {
		t.Fatalf("unexpected create payload metadata: %#v", payload)
	}
	if len(payload.Regions) != 2 || payload.Regions["us-east-1"] == 0 || payload.Regions["us-west-2"] == 0 {
		t.Fatalf("unexpected create payload regions: %#v", payload.Regions)
	}
	if payload.UseForwardAccountToAssumeRole == nil || !*payload.UseForwardAccountToAssumeRole {
		t.Fatalf("expected Forward assume-role credential mode: %#v", payload)
	}
	infos := payload.AssumeRoleInfos
	if len(infos) != 2 {
		t.Fatalf("expected two assume role entries, got %#v", infos)
	}
	if infos[1].RoleArn != "arn:aws:iam::222222222222:role/ForwardRole" || infos[1].ExternalID != "Org:123" {
		t.Fatalf("unexpected assume role entry: %#v", infos[1])
	}

	var manualPayloads []ManualAccountData
	data, err = os.ReadFile(manual)
	if err != nil {
		t.Fatalf("read manual: %v", err)
	}
	if err := json.Unmarshal(data, &manualPayloads); err != nil {
		t.Fatalf("decode manual: %v", err)
	}
	if strings.Contains(string(data), "errorMsg") {
		t.Fatalf("manual payload should omit empty errorMsg fields: %s", string(data))
	}
	if len(manualPayloads) != 2 {
		t.Fatalf("unexpected manual payload: %#v", manualPayloads)
	}
	if manualPayloads[1].ID != "222222222222" || manualPayloads[1].Name != "app" || manualPayloads[1].RoleArn == nil || *manualPayloads[1].RoleArn != "arn:aws:iam::222222222222:role/ForwardRole" {
		t.Fatalf("unexpected manual payload entry: %#v", manualPayloads[1])
	}
	if manualPayloads[1].ExternalID == nil || *manualPayloads[1].ExternalID != "Org:123" {
		t.Fatalf("expected manual external id: %#v", manualPayloads[1])
	}
}

func TestRunAWSOrganizationsWithForwardFetchesExternalIDAndPostsCreate(t *testing.T) {
	var sawCloudAccounts bool
	var sawExternalID bool
	var posted api.CreateAWSPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks":
			_, _ = w.Write([]byte(`[{"id":"network-1","name":"prod"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			sawCloudAccounts = true
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts/aws/assumeRole/externalId":
			sawExternalID = true
			_, _ = w.Write([]byte(`{"externalId":"Org:55"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatalf("decode posted payload: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "payload.json")
	source := AWSOrganizationSource{Accounts: []AWSOrganizationAccount{{ID: "222222222222", Name: "new"}}}
	summary, err := RunAWSOrganizations(context.Background(), AWSOrganizationConfig{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		SetupIDs:  []string{"aws-prod"},
		RoleName:  "ForwardRole",
		Regions:   []string{"us-east-1"},
		Output:    output,
		Post:      true,
		APIPrefix: "/api",
	}, source)
	if err != nil {
		t.Fatalf("RunAWSOrganizations() error = %v", err)
	}
	if !sawCloudAccounts || !sawExternalID {
		t.Fatalf("expected Forward metadata requests: cloudAccounts=%t externalID=%t", sawCloudAccounts, sawExternalID)
	}
	if summary.PostedSetupCount != 1 || summary.PatchedSetupCount != 0 {
		t.Fatalf("unexpected post/patch counts: %#v", summary)
	}
	if posted.Name != "aws-prod" || posted.AssumeRoleInfos[0].ExternalID != "Org:55" {
		t.Fatalf("unexpected posted payload: %#v", posted)
	}
	if posted.UseForwardAccountToAssumeRole == nil || !*posted.UseForwardAccountToAssumeRole {
		t.Fatalf("expected Forward assume-role mode in posted payload: %#v", posted)
	}
	var payload api.CreateAWSPayload
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if payload.AssumeRoleInfos[0].RoleArn != "arn:aws:iam::222222222222:role/ForwardRole" {
		t.Fatalf("unexpected generated role: %#v", payload.AssumeRoleInfos[0])
	}
}

func TestRunAWSOrganizationsStaticKeysWritesPlaceholderWhenSecretMissing(t *testing.T) {
	output := filepath.Join(t.TempDir(), "payload.json")
	source := AWSOrganizationSource{Accounts: []AWSOrganizationAccount{{ID: "222222222222", Name: "app"}}}

	summary, err := RunAWSOrganizations(context.Background(), AWSOrganizationConfig{
		SetupIDs:             []string{"aws-prod"},
		RoleName:             "ForwardRole",
		Regions:              []string{"us-east-1"},
		CredentialMode:       CredentialModeStaticKeys,
		CollectorAccessKeyID: "AKIAEXAMPLE",
		Output:               output,
	}, source)
	if err != nil {
		t.Fatalf("RunAWSOrganizations() error = %v", err)
	}
	if summary.CreatePayloadReady {
		t.Fatalf("expected payload to require secret before POST: %#v", summary)
	}

	var payload api.CreateAWSPayload
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if payload.Username != "AKIAEXAMPLE" || payload.Password != collectorSecretPlaceholder {
		t.Fatalf("unexpected static key fields: %#v", payload)
	}
	if payload.UseForwardAccountToAssumeRole == nil || *payload.UseForwardAccountToAssumeRole {
		t.Fatalf("expected static-key credential mode: %#v", payload)
	}
}

func TestRunAWSOrganizationsRejectsExistingForwardSetup(t *testing.T) {
	var posted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks":
			_, _ = w.Write([]byte(`[{"id":"network-1","name":"prod"}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"aws-prod"}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			posted = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := RunAWSOrganizations(context.Background(), AWSOrganizationConfig{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		SetupIDs:  []string{"aws-prod"},
		RoleName:  "ForwardRole",
		Regions:   []string{"us-east-1"},
		Output:    filepath.Join(t.TempDir(), "payload.json"),
		Post:      true,
		APIPrefix: "/api",
	}, AWSOrganizationSource{Accounts: []AWSOrganizationAccount{{ID: "222222222222", Name: "app"}}})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate setup error, got %v", err)
	}
	if posted {
		t.Fatal("expected no create call for existing setup")
	}
}

func TestBuildPlanPreservesRegionProxyMap(t *testing.T) {
	items := []map[string]any{{"Cloud Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a"}}
	cloudAccounts := []api.CloudAccount{{
		Name:                  "setup-a",
		RegionToProxyServerID: map[string]string{"us-east-1": "proxy-east"},
		AssumeRoleInfos:       []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true}},
	}}

	plan, err := buildPlan(items, cloudAccounts, "", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if plan.Payloads["setup-a"].RegionToProxyServerID["us-east-1"] != "proxy-east" {
		t.Fatalf("expected region proxy map to be preserved: %#v", plan.Payloads["setup-a"])
	}
}

func TestBuildPlanSupportsRoleARNsWithoutExternalID(t *testing.T) {
	items := []map[string]any{
		{"Cloud Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "kept"},
		{"Cloud Setup ID": "setup-a", "Cloud Account ID": "222", "Cloud Account Name": "added"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111", AccountName: "kept", RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true},
		},
	}}

	plan, err := buildPlan(items, cloudAccounts, "", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	setup := plan.Setups[0]
	if setup.RoleName != "ForwardRole" || setup.ExternalIDConfigured {
		t.Fatalf("expected role metadata without external ID: %#v", setup)
	}
	infos := plan.Payloads["setup-a"].AssumeRoleInfos
	if len(infos) != 2 {
		t.Fatalf("expected 2 account entries, got %#v", infos)
	}
	if infos[0].ExternalID != "" || infos[1].ExternalID != "" {
		t.Fatalf("external ID should not be added when absent from setup: %#v", infos)
	}
	if infos[1].RoleArn != "arn:aws:iam::222:role/ForwardRole" {
		t.Fatalf("unexpected generated role ARN: %#v", infos[1])
	}
	if infos[1].AccountID != "222" || infos[1].AccountName != "added" || !infos[1].Enabled {
		t.Fatalf("unexpected added account entry: %#v", infos[1])
	}
}

func TestBuildPlanPreservesGovCloudRolePartition(t *testing.T) {
	items := []map[string]any{
		{"Cloud Setup ID": "setup-gov", "Cloud Account ID": "111111111111", "Cloud Account Name": "kept"},
		{"Cloud Setup ID": "setup-gov", "Cloud Account ID": "222222222222", "Cloud Account Name": "added"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-gov",
		AssumeRoleInfos: []api.AssumeRoleInfo{{
			AccountID: "111111111111",
			RoleArn:   "arn:aws-us-gov:iam::111111111111:role/ForwardRole",
			Enabled:   true,
		}},
	}}

	plan, err := buildPlan(items, cloudAccounts, "", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	want := "arn:aws-us-gov:iam::222222222222:role/ForwardRole"
	if got := plan.Payloads["setup-gov"].AssumeRoleInfos[1].RoleArn; got != want {
		t.Fatalf("new account role ARN = %q, want %q", got, want)
	}
}

func TestBuildPlanRejectsMixedOrMismatchedAWSPartitions(t *testing.T) {
	items := []map[string]any{{"Cloud Setup ID": "setup-gov", "Cloud Account ID": "111111111111"}}
	for name, setup := range map[string]api.CloudAccount{
		"mixed roles": {
			Name: "setup-gov",
			AssumeRoleInfos: []api.AssumeRoleInfo{
				{RoleArn: "arn:aws-us-gov:iam::111111111111:role/ForwardRole"},
				{RoleArn: "arn:aws:iam::222222222222:role/ForwardRole"},
			},
		},
		"region mismatch": {
			Name:            "setup-gov",
			Regions:         map[string]api.RegionMeta{"us-gov-west-1": {TestInstant: 1}},
			AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111111111111:role/ForwardRole"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPlan(items, []api.CloudAccount{setup}, "", nil); err == nil {
				t.Fatal("expected unsafe partition plan to fail")
			}
		})
	}
}

func TestRunBlocksGovCloudRemovalWithoutOrgEvidenceEvenWithBreakGlassFlags(t *testing.T) {
	patched := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			_, _ = w.Write([]byte(`{"items":[{"Cloud Setup ID":"gov-prod","Cloud Account ID":"111111111111","Cloud Account Name":"keep","Collected?":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"gov-prod","regions":{"us-gov-west-1":{"testInstant":1}},"assumeRoleInfos":[
              {"accountId":"111111111111","roleArn":"arn:aws-us-gov:iam::111111111111:role/ForwardRole","enabled":true},
              {"accountId":"222222222222","roleArn":"arn:aws-us-gov:iam::222222222222:role/ForwardRole","enabled":true}
            ]}]`))
		case r.Method == http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:               server.URL,
		Username:           "user",
		Password:           "pass",
		NetworkID:          "network-1",
		SnapshotID:         "snapshot-1",
		SetupIDs:           []string{"gov-prod"},
		Output:             filepath.Join(t.TempDir(), "plan.json"),
		APIPrefix:          "/api",
		Insecure:           true,
		Apply:              true,
		AllowRemovals:      true,
		MaxRemovals:        1,
		MaxRemovalPercent:  50,
		AllowNoCandidates:  true,
		AllowNoOrgEvidence: true,
	})
	if err == nil || !strings.Contains(err.Error(), "GovCloud account removals require positive AWS Organizations evidence") {
		t.Fatalf("expected GovCloud Organizations safety block, got %v", err)
	}
	if patched {
		t.Fatal("unsafe GovCloud removal reached PATCH")
	}
}

func TestBuildPlanFiltersRequestedSetupIDs(t *testing.T) {
	items := []map[string]any{
		{"Cloud Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a"},
		{"Cloud Setup ID": "setup-b", "Cloud Account ID": "222", "Cloud Account Name": "acct-b"},
	}
	cloudAccounts := []api.CloudAccount{
		{Name: "setup-a", AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true}}},
		{Name: "setup-b", AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::222:role/ForwardRole", Enabled: true}}},
	}

	plan, err := buildPlan(items, cloudAccounts, "", []string{"setup-b"})
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if len(plan.Setups) != 1 || plan.Setups[0].SetupID != "setup-b" {
		t.Fatalf("unexpected filtered plan: %#v", plan.Setups)
	}
}

func TestBuildPlanPreservesNonOrgExternalID(t *testing.T) {
	items := []map[string]any{{"Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a"}}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{{
			RoleArn:    "arn:aws:iam::111:role/ForwardRole",
			ExternalID: "customer-managed-external-id",
			Enabled:    true,
		}},
	}}

	plan, err := buildPlan(items, cloudAccounts, "custom-query", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	info := plan.Payloads["setup-a"].AssumeRoleInfos[0]
	if info.ExternalID != "customer-managed-external-id" {
		t.Fatalf("expected external id to be preserved, got %#v", info)
	}
	if plan.Setups[0].OrgID != 0 {
		t.Fatalf("custom external id should not be reported as an org id: %#v", plan.Setups[0])
	}
	if !plan.Setups[0].ExternalIDConfigured {
		t.Fatalf("expected custom external id to be reported as configured: %#v", plan.Setups[0])
	}
}

func TestBuildPlanPreservesMixedPerAccountExternalIDs(t *testing.T) {
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "one"},
		{"Setup ID": "setup-a", "Cloud Account ID": "222222222222", "Cloud Account Name": "two"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111111111111", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole", ExternalID: "one-id", Enabled: true},
			{AccountID: "222222222222", RoleArn: "arn:aws:iam::222222222222:role/ForwardRole", ExternalID: "two-id", Enabled: true},
		},
	}}

	plan, err := buildPlan(items, cloudAccounts, "", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	infos := plan.Payloads["setup-a"].AssumeRoleInfos
	if infos[0].ExternalID != "one-id" || infos[1].ExternalID != "two-id" {
		t.Fatalf("mixed External IDs were not preserved: %#v", infos)
	}
	if !plan.Setups[0].ExternalIDConfigured || plan.Setups[0].ExternalIDConsistent || plan.Setups[0].OrgID != 0 {
		t.Fatalf("unexpected mixed External ID summary: %#v", plan.Setups[0])
	}
}

func TestBuildPlanRequiresAssignmentsForNewAccountsInMixedSetup(t *testing.T) {
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "one"},
		{"Setup ID": "setup-a", "Cloud Account ID": "222222222222", "Cloud Account Name": "two"},
		{"Setup ID": "setup-a", "Cloud Account ID": "333333333333", "Cloud Account Name": "three"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111111111111", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole", ExternalID: "one-id", Enabled: true},
			{AccountID: "222222222222", RoleArn: "arn:aws:iam::222222222222:role/ForwardRole", ExternalID: "two-id", Enabled: true},
		},
	}}

	if _, err := buildPlan(items, cloudAccounts, "", nil); err == nil || !strings.Contains(err.Error(), "provide --external-id-file assignments") {
		t.Fatalf("expected fail-closed mixed-ID addition error, got %v", err)
	}
	plan, err := buildPlanWithOptions(items, cloudAccounts, "", nil, buildPlanOptions{
		ExternalIDByAccount: externalIDAssignments{
			"setup-a": {"333333333333": "three-id"},
		},
	})
	if err != nil {
		t.Fatalf("buildPlanWithOptions() error = %v", err)
	}
	infos := plan.Payloads["setup-a"].AssumeRoleInfos
	if infos[0].ExternalID != "one-id" || infos[1].ExternalID != "two-id" || infos[2].ExternalID != "three-id" {
		t.Fatalf("unexpected assigned mixed-ID payload: %#v", infos)
	}
}

func TestBuildPlanForConfigLoadsPerAccountExternalIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "external-ids.csv")
	contents := "setup_id,account_id,action,external_id\nsetup-a,333333333333,set,three-id\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "one"},
		{"Setup ID": "setup-a", "Cloud Account ID": "222222222222", "Cloud Account Name": "two"},
		{"Setup ID": "setup-a", "Cloud Account ID": "333333333333", "Cloud Account Name": "three"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111111111111", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole", ExternalID: "one-id", Enabled: true},
			{AccountID: "222222222222", RoleArn: "arn:aws:iam::222222222222:role/ForwardRole", ExternalID: "two-id", Enabled: true},
		},
	}}
	plan, err := buildPlanForConfig(Config{ExternalIDFile: path}, items, cloudAccounts)
	if err != nil {
		t.Fatalf("buildPlanForConfig() error = %v", err)
	}
	if got := plan.Payloads["setup-a"].AssumeRoleInfos[2].ExternalID; got != "three-id" {
		t.Fatalf("new account External ID = %q, want three-id", got)
	}
}

func TestBuildPlanAllowsMultipleSetupsWithDefaultQueryWhenRowsHaveSetupIDs(t *testing.T) {
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "acct-a"},
		{"Setup ID": "setup-b", "Cloud Account ID": "222", "Cloud Account Name": "acct-b"},
	}
	cloudAccounts := []api.CloudAccount{
		{Name: "setup-a", AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true}}},
		{Name: "setup-b", AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::222:role/ForwardRole", Enabled: true}}},
	}

	plan, err := buildPlan(items, cloudAccounts, DefaultQueryID, nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if len(plan.Setups) != 2 {
		t.Fatalf("expected 2 setups, got %#v", plan.Setups)
	}
}

func TestBuildPlanRejectsMultipleSetupsWithoutSetupIDs(t *testing.T) {
	items := []map[string]any{{"Cloud Account ID": "111", "Cloud Account Name": "acct-a"}}
	_, err := buildPlan(items, []api.CloudAccount{{Name: "setup-a"}, {Name: "setup-b"}}, DefaultQueryID, nil)
	if err == nil || !strings.Contains(err.Error(), "no setup ID data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildPlanReportsAccountDiff(t *testing.T) {
	items := []map[string]any{
		{"Setup ID": "setup-a", "Cloud Account ID": "111", "Cloud Account Name": "kept"},
		{"Setup ID": "setup-a", "Cloud Account ID": "222", "Cloud Account Name": "added"},
	}
	cloudAccounts := []api.CloudAccount{{
		Name: "setup-a",
		AssumeRoleInfos: []api.AssumeRoleInfo{
			{AccountID: "111", AccountName: "kept", RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true},
			{AccountID: "333", AccountName: "removed", RoleArn: "arn:aws:iam::333:role/ForwardRole", Enabled: true},
		},
	}}

	plan, err := buildPlan(items, cloudAccounts, "custom-query", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	setup := plan.Setups[0]
	if len(setup.AddedAccounts) != 1 || setup.AddedAccounts[0].AccountID != "222" {
		t.Fatalf("unexpected added accounts: %#v", setup.AddedAccounts)
	}
	if len(setup.RemovedAccounts) != 1 || setup.RemovedAccounts[0].AccountID != "333" {
		t.Fatalf("unexpected removed accounts: %#v", setup.RemovedAccounts)
	}
	if len(setup.UnchangedAccounts) != 1 || setup.UnchangedAccounts[0].AccountID != "111" {
		t.Fatalf("unexpected unchanged accounts: %#v", setup.UnchangedAccounts)
	}
	if !plan.HasRemovals() {
		t.Fatal("expected plan to report removals")
	}
}

func TestRunWritesPayloadAndPatchesWhenApplyEnabled(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","regions":{"us-east-1":{"testInstant":123}},"assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","externalId":"Org:99","enabled":true}],"proxyServerId":"proxy-1"}]`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "payload.json")
	summary, err := Run(context.Background(), Config{
		Host:      server.URL,
		Username:  "alice",
		Password:  "secret",
		NetworkID: "network-1",
		QueryID:   "custom-query",
		Output:    output,
		APIPrefix: "/api",
		Insecure:  true,
		Apply:     true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.PatchedSetupCount != 1 || len(patched) != 1 {
		t.Fatalf("unexpected patch counts: summary=%+v patched=%v", summary, patched)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var payloads map[string]api.PatchPayload
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if payloads["setup-a"].AssumeRoleInfos[0].RoleArn != "arn:aws:iam::111:role/ForwardRole" {
		t.Fatalf("unexpected payload: %#v", payloads["setup-a"])
	}
	if payloads["setup-a"].ProxyServerID != "proxy-1" {
		t.Fatalf("unexpected proxy in payload: %#v", payloads["setup-a"])
	}
}

func TestRunWritesManualPayloadWhenRequested(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","externalId":"Org:99","enabled":true}],"proxyServerId":"proxy-1"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "payload.json")
	manual := filepath.Join(t.TempDir(), "manual_payload.json")
	summary, err := Run(context.Background(), Config{
		Host:         server.URL,
		Username:     "alice",
		Password:     "secret",
		NetworkID:    "network-1",
		QueryID:      "custom-query",
		Output:       output,
		ManualOutput: manual,
		APIPrefix:    "/api",
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.ManualOutput != manual {
		t.Fatalf("expected manual_output path %q, got %#v", manual, summary.ManualOutput)
	}
	if summary.ManualPayloadSHA256 == "" {
		t.Fatalf("expected manual payload sha in summary")
	}
	if len(summary.ManualPayloads["setup-a"]) != 1 {
		t.Fatalf("expected manual payload in summary, got %#v", summary.ManualPayloads)
	}

	data, err := os.ReadFile(manual)
	if err != nil {
		t.Fatalf("read manual output: %v", err)
	}
	var manualPayloads map[string][]api.AssumeRoleInfo
	if err := json.Unmarshal(data, &manualPayloads); err != nil {
		t.Fatalf("decode manual output: %v", err)
	}
	accounts := manualPayloads["setup-a"]
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account in manual output, got %#v", accounts)
	}
	if accounts[0].RoleArn != "arn:aws:iam::111:role/ForwardRole" {
		t.Fatalf("unexpected manual role arn: %#v", accounts[0])
	}
	if accounts[0].AccountID != "111" {
		t.Fatalf("expected account 111 in manual output, got %#v", accounts[0])
	}
}

func TestRunBlocksApplyWithRemovalsUnlessAllowed(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:      server.URL,
		Username:  "alice",
		Password:  "secret",
		NetworkID: "network-1",
		QueryID:   "custom-query",
		Output:    filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix: "/api",
		Insecure:  true,
		Apply:     true,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-removals") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patched) != 0 {
		t.Fatalf("expected no patch calls, got %v", patched)
	}
}

func TestRunAllowsApplyWithRemovalsWhenExplicitlyAllowed(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	summary, err := Run(context.Background(), Config{
		Host:               server.URL,
		Username:           "alice",
		Password:           "secret",
		NetworkID:          "network-1",
		QueryID:            "custom-query",
		Output:             filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:          "/api",
		Insecure:           true,
		Apply:              true,
		AllowRemovals:      true,
		AllowNoCandidates:  true,
		AllowNoOrgEvidence: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.PatchedSetupCount != 1 || len(patched) != 1 {
		t.Fatalf("unexpected patch result summary=%+v patched=%v", summary, patched)
	}
	if len(summary.PlannedSetups[0].RemovedAccounts) != 1 {
		t.Fatalf("expected removed account in summary: %+v", summary.PlannedSetups[0])
	}
}

func TestRunBlocksApplyWithNoOrgEvidenceWhenNoCandidatesVisibleAndExplicitNoEvidenceFlagMissing(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:              server.URL,
		Username:          "alice",
		Password:          "secret",
		NetworkID:         "network-1",
		QueryID:           "custom-query",
		Output:            filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:         "/api",
		Insecure:          true,
		Apply:             true,
		AllowRemovals:     true,
		AllowNoCandidates: true,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-no-org-evidence") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patched) != 0 {
		t.Fatalf("expected no patch calls, got %v", patched)
	}
}

func TestRunAllowsApplyWithNoOrgEvidenceWhenExplicitNoEvidenceFlagSet(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	summary, err := Run(context.Background(), Config{
		Host:               server.URL,
		Username:           "alice",
		Password:           "secret",
		NetworkID:          "network-1",
		QueryID:            "custom-query",
		Output:             filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:          "/api",
		Insecure:           true,
		Apply:              true,
		AllowRemovals:      true,
		AllowNoCandidates:  true,
		AllowNoOrgEvidence: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.PatchedSetupCount != 1 || len(patched) != 1 {
		t.Fatalf("unexpected patch result summary=%+v patched=%v", summary, patched)
	}
	if len(summary.PlannedSetups[0].RemovedAccounts) != 1 {
		t.Fatalf("expected removed account in summary: %+v", summary.PlannedSetups[0])
	}
}

func TestRunBlocksApplyWithNoOrgEvidenceInMultiSetup(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":false},
				{"Cloud Setup ID":"setup-b","Cloud Account ID":"222","Cloud Account Name":"acct-b","Collected?":true}
			]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}]},
				{"name":"setup-b","assumeRoleInfos":[{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true},{"accountId":"333","roleArn":"arn:aws:iam::333:role/ForwardRole","enabled":true}]}
			]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:               server.URL,
		Username:           "alice",
		Password:           "secret",
		NetworkID:          "network-1",
		QueryID:            "custom-query",
		Output:             filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:          "/api",
		Insecure:           true,
		Apply:              true,
		AllowRemovals:      true,
		AllowNoCandidates:  true,
		AllowNoOrgEvidence: false,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-no-org-evidence") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "setup-b") {
		t.Fatalf("expected error to identify missing org evidence setup: %v", err)
	}
	if len(patched) != 0 {
		t.Fatalf("expected no patch calls, got %v", patched)
	}
}

func TestRunAllowsApplyWithNoOrgEvidenceWhenExplicitNoEvidenceFlagSetForMultiSetup(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[
				{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":false},
				{"Cloud Setup ID":"setup-b","Cloud Account ID":"222","Cloud Account Name":"acct-b","Collected?":true}
			]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}]},
				{"name":"setup-b","assumeRoleInfos":[{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true},{"accountId":"333","roleArn":"arn:aws:iam::333:role/ForwardRole","enabled":true}]}
			]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	summary, err := Run(context.Background(), Config{
		Host:               server.URL,
		Username:           "alice",
		Password:           "secret",
		NetworkID:          "network-1",
		QueryID:            "custom-query",
		Output:             filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:          "/api",
		Insecure:           true,
		Apply:              true,
		AllowRemovals:      true,
		AllowNoCandidates:  true,
		AllowNoOrgEvidence: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.PatchedSetupCount != 2 || len(patched) != 2 {
		t.Fatalf("expected patches for 2 setups: summary=%+v patched=%v", summary, patched)
	}
	var setupBRemoved int
	for _, setup := range summary.PlannedSetups {
		if setup.SetupID != "setup-b" {
			continue
		}
		setupBRemoved = len(setup.RemovedAccounts)
	}
	if setupBRemoved != 1 {
		t.Fatalf("expected removals on setup-b, got %d in setups=%+v", setupBRemoved, summary.PlannedSetups)
	}
}

func TestRunBlocksRemovalsWhenNoCandidatesVisible(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},{"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = append(patched, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:          server.URL,
		Username:      "alice",
		Password:      "secret",
		NetworkID:     "network-1",
		QueryID:       "custom-query",
		Output:        filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:     "/api",
		Insecure:      true,
		Apply:         true,
		AllowRemovals: true,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-no-candidates") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patched) != 0 {
		t.Fatalf("expected no patch calls, got %v", patched)
	}
}

func TestRunUsesExplicitSnapshotIDForNQE(t *testing.T) {
	var seenQuery string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			seenQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}]}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:       server.URL,
		Username:   "alice",
		Password:   "secret",
		NetworkID:  "network-1",
		SnapshotID: "snapshot-1",
		QueryID:    "custom-query",
		Output:     filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:  "/api",
		Insecure:   true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if seenQuery != "networkId=network-1&snapshotId=snapshot-1" && seenQuery != "snapshotId=snapshot-1&networkId=network-1" {
		t.Fatalf("unexpected NQE query string %q", seenQuery)
	}
}

func TestRunRejectsStaleLatestProcessedSnapshot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/snapshots/latestProcessed" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"old","processedAt":"2020-01-01T00:00:00Z"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := Run(context.Background(), Config{
		Host:           server.URL,
		Username:       "alice",
		Password:       "secret",
		NetworkID:      "network-1",
		QueryID:        "custom-query",
		Output:         filepath.Join(t.TempDir(), "payload.json"),
		APIPrefix:      "/api",
		Insecure:       true,
		MaxSnapshotAge: time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunFallsBackToSingleSetupWhenQueryLacksSetupID(t *testing.T) {
	items := []map[string]any{{"Cloud Account ID": "111", "Cloud Account Name": "acct-a"}}
	cloudAccounts := []api.CloudAccount{{
		Name:            "setup-only",
		AssumeRoleInfos: []api.AssumeRoleInfo{{RoleArn: "arn:aws:iam::111:role/ForwardRole", Enabled: true}},
	}}
	plan, err := buildPlan(items, cloudAccounts, DefaultQueryID+"-customized", nil)
	if err != nil {
		t.Fatalf("buildPlan() error = %v", err)
	}
	if len(plan.Setups) != 1 || plan.Setups[0].SetupID != "setup-only" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestWriteJSONPayloadIsAtomicAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed payload: %v", err)
	}

	outputPath, _, err := writeJSONPayload(path, map[string]string{"password": "sensitive"})
	if err != nil {
		t.Fatalf("writeJSONPayload() error = %v", err)
	}
	if outputPath != path {
		t.Fatalf("unexpected output path %q", outputPath)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat payload: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected mode 0600, got %04o", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !strings.Contains(string(data), `"password": "sensitive"`) {
		t.Fatalf("unexpected payload contents: %s", data)
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".payload.json.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary files were not cleaned up: %#v", temps)
	}
}
