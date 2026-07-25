package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestApplyPlanPatchesReviewedPayload(t *testing.T) {
	var patched []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts" {
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"setup-a","assumeRoleInfos":[]}]`))
			return
		}
		if r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		patched = append(patched, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(
		planPath,
		[]byte(`{"setup-a":{"type":"AWS","name":"setup-a","regionToProxyServerId":{},"assumeRoleInfos":[
			{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true}
		]}}`),
		0o644,
	); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	summary, err := ApplyPlan(context.Background(), ApplyPlanConfig{
		Host:      server.URL,
		Username:  "alice",
		Password:  "secret",
		NetworkID: "network-1",
		PlanPath:  planPath,
		APIPrefix: "/api",
		Insecure:  true,
	})
	if err != nil {
		t.Fatalf("ApplyPlan() error = %v", err)
	}
	if summary.PatchedSetupCount != 1 || len(patched) != 1 {
		t.Fatalf("unexpected patch result summary=%+v patched=%v", summary, patched)
	}
	if patched[0] != "/api/networks/network-1/cloudAccounts/setup-a" {
		t.Fatalf("unexpected patch path %q", patched[0])
	}
	if summary.PayloadSHA256 == "" {
		t.Fatalf("expected payload sha: %+v", summary)
	}
	if summary.RollbackOutput == "" || summary.RollbackSHA256 == "" {
		t.Fatalf("expected pre-apply rollback artifact: %+v", summary)
	}
	if _, err := os.Stat(summary.RollbackOutput); err != nil {
		t.Fatalf("expected rollback file: %v", err)
	}
}

func TestApplyPlanAcceptsPreBranchBinaryArtifacts(t *testing.T) {
	tests := []struct {
		name        string
		artifact    string
		baseline    string
		wantEnabled bool
	}{
		{
			name:        "generated apply plan",
			artifact:    "pre_branch_apply_plan.json",
			baseline:    "pre_branch_apply_plan.rollback.json",
			wantEnabled: true,
		},
		{
			name:        "generated rollback",
			artifact:    "pre_branch_apply_plan.rollback.json",
			baseline:    "pre_branch_apply_plan.json",
			wantEnabled: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			planPath, targetPayloads := materializePreBranchJSONArtifact(t, test.artifact)
			_, baselinePayloads := materializePreBranchJSONArtifact(t, test.baseline)
			baseline := baselinePayloads["setup-a"]
			current := api.CloudAccount{
				Type:                  baseline.Type,
				Name:                  baseline.Name,
				ProxyServerID:         baseline.ProxyServerID,
				RegionToProxyServerID: baseline.RegionToProxyServerID,
				Regions:               make(map[string]api.RegionMeta, len(baseline.Regions)),
				AssumeRoleInfos:       baseline.AssumeRoleInfos,
			}
			for region, instant := range baseline.Regions {
				current.Regions[region] = api.RegionMeta{TestInstant: instant}
			}

			patchCount := 0
			var patched api.PatchPayload
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
					_ = json.NewEncoder(w).Encode([]api.CloudAccount{current})
				case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
					patchCount++
					if err := json.NewDecoder(r.Body).Decode(&patched); err != nil {
						t.Fatalf("decode PATCH: %v", err)
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			summary, err := ApplyPlan(context.Background(), ApplyPlanConfig{
				Host:                       server.URL,
				Username:                   "alice",
				Password:                   "secret",
				NetworkID:                  "network-1",
				PlanPath:                   planPath,
				APIPrefix:                  "/api",
				AllowRemovals:              true,
				MaxRemovals:                2,
				MaxRemovalPercent:          100,
				AllowUnattendedDestructive: true,
			})
			if err != nil {
				t.Fatalf("ApplyPlan() with %s: %v", test.artifact, err)
			}
			if patchCount != 1 || summary.PatchedSetupCount != 1 {
				t.Fatalf("patch count = %d, summary = %+v; want one PATCH", patchCount, summary)
			}
			if summary.ResultJournalOutput == "" {
				t.Fatalf("accepted artifact did not produce a result journal: %+v", summary)
			}
			want := targetPayloads["setup-a"]
			if len(patched.AssumeRoleInfos) != 2 || patched.AssumeRoleInfos[1].Enabled != test.wantEnabled {
				t.Fatalf("old artifact account state was misread: %#v", patched.AssumeRoleInfos)
			}
			if patched.ProxyServerID != want.ProxyServerID || patched.Regions["us-east-1"] != 123 {
				t.Fatalf("old artifact recovery fields were misread: %#v", patched)
			}
		})
	}
}

func materializePreBranchJSONArtifact(t *testing.T, name string) (string, map[string]api.PatchPayload) {
	t.Helper()
	wantSHA256 := map[string]string{
		"pre_branch_apply_plan.json":          "da2612db7cbd41071306e6a8d28404d36de74ae98ebb9dd9ecf2c28dfa63738e",
		"pre_branch_apply_plan.rollback.json": "804a9a15d5aab5e5b65ff796990d61ad17bc64df9e59fcc3d5fbf385c94565b5",
	}[name]
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read pre-branch artifact %s: %v", name, err)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != wantSHA256 {
		t.Fatalf("pre-branch artifact %s SHA-256 = %s; want %s", name, got, wantSHA256)
	}
	var payloads map[string]api.PatchPayload
	if err := json.Unmarshal(data, &payloads); err != nil {
		t.Fatalf("decode pre-branch artifact %s in test setup: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("materialize pre-branch artifact %s: %v", name, err)
	}
	return path, payloads
}

func TestApplyPlanSuppressesZeroDiffPatch(t *testing.T) {
	patchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"setup-a","assumeRoleInfos":[
				{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true}
			]}]`))
		case r.Method == http.MethodPatch:
			patchCount++
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "same.json")
	if err := os.WriteFile(planPath, []byte(`{"setup-a":{"type":"AWS","name":"setup-a","regionToProxyServerId":{},"assumeRoleInfos":[
		{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true}
	]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := ApplyPlan(context.Background(), ApplyPlanConfig{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		PlanPath:  planPath,
		APIPrefix: "/api",
	})
	if err != nil {
		t.Fatalf("ApplyPlan() error = %v", err)
	}
	if patchCount != 0 || summary.PatchedSetupCount != 0 {
		t.Fatalf("zero-diff apply = (patches=%d, summary=%+v), want no PATCH", patchCount, summary)
	}
	if summary.ResultJournalOutput == "" {
		t.Fatalf("zero-diff apply did not persist a result journal: %+v", summary)
	}
	if summary.RollbackOutput != "" {
		t.Fatalf("zero-diff apply unexpectedly wrote rollback output: %+v", summary)
	}
}

func TestApplyPlanDisableRequiresGatewayDestructiveAuthorization(t *testing.T) {
	tests := []struct {
		name              string
		allowRemovals     bool
		maxRemovals       int
		maxRemovalPercent float64
		allowUnattended   bool
		wantError         string
	}{
		{name: "no destructive authorization", wantError: "--allow-removals"},
		{name: "authorization without bounds", allowRemovals: true, wantError: "require both"},
		{
			name:              "unattended authorization required",
			allowRemovals:     true,
			maxRemovals:       2,
			maxRemovalPercent: 100,
			wantError:         "--allow-unattended-destructive",
		},
		{
			name:              "fully authorized",
			allowRemovals:     true,
			maxRemovals:       2,
			maxRemovalPercent: 100,
			allowUnattended:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patchCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
					_, _ = w.Write([]byte(`[{"type":"AWS","name":"prod","assumeRoleInfos":[
						{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true},
						{"accountId":"222222222222","roleArn":"arn:aws:iam::222222222222:role/ForwardRole","enabled":true}
					]}]`))
				case r.Method == http.MethodPatch:
					patchCount++
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			planPath := filepath.Join(t.TempDir(), "disable.json")
			if err := os.WriteFile(planPath, []byte(`{"prod":{"type":"AWS","name":"prod","assumeRoleInfos":[
				{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":false},
				{"accountId":"222222222222","roleArn":"arn:aws:iam::222222222222:role/ForwardRole","enabled":false}
			]}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
				Host:                       server.URL,
				Username:                   "user",
				Password:                   "pass",
				NetworkID:                  "network-1",
				PlanPath:                   planPath,
				APIPrefix:                  "/api",
				AllowRemovals:              test.allowRemovals,
				MaxRemovals:                test.maxRemovals,
				MaxRemovalPercent:          test.maxRemovalPercent,
				AllowUnattendedDestructive: test.allowUnattended,
			})
			if test.wantError == "" {
				if err != nil || patchCount != 1 {
					t.Fatalf("fully authorized disable = (patches=%d, err=%v), want one PATCH", patchCount, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ApplyPlan() error = %v, want %q", err, test.wantError)
			}
			if patchCount != 0 {
				t.Fatalf("unauthorized disable PATCH count = %d, want 0", patchCount)
			}
		})
	}
}

func TestApplyPlanCannotBypassGovCloudRemovalSafety(t *testing.T) {
	patched := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"gov-prod","regions":{"us-gov-west-1":{"testInstant":1}},"assumeRoleInfos":[
              {"accountId":"111111111111","roleArn":"arn:aws-us-gov:iam::111111111111:role/ForwardRole","enabled":true},
              {"accountId":"222222222222","roleArn":"arn:aws-us-gov:iam::222222222222:role/ForwardRole","enabled":true}
            ]}]`))
		case r.Method == http.MethodPatch:
			patched = true
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(planPath, []byte(`{"gov-prod":{"type":"AWS","name":"gov-prod","regions":{"us-gov-west-1":1},"assumeRoleInfos":[
      {"accountId":"111111111111","roleArn":"arn:aws-us-gov:iam::111111111111:role/ForwardRole","enabled":true}
    ]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
		Host:                       server.URL,
		Username:                   "user",
		Password:                   "pass",
		NetworkID:                  "network-1",
		PlanPath:                   planPath,
		APIPrefix:                  "/api",
		AllowRemovals:              true,
		MaxRemovals:                1,
		MaxRemovalPercent:          100,
		AllowUnattendedDestructive: true,
	})
	if err == nil || !strings.Contains(err.Error(), "GovCloud account removals require positive AWS Organizations evidence") {
		t.Fatalf("expected GovCloud apply-plan block, got %v", err)
	}
	if patched {
		t.Fatal("unsafe GovCloud apply-plan reached PATCH")
	}
}

func TestApplyPlanBlocksRemovalPercentageAboveLimit(t *testing.T) {
	patched := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"prod","assumeRoleInfos":[
              {"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true},
              {"accountId":"222222222222","roleArn":"arn:aws:iam::222222222222:role/ForwardRole","enabled":true}
            ]}]`))
		case r.Method == http.MethodPatch:
			patched = true
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(planPath, []byte(`{"prod":{"type":"AWS","name":"prod","assumeRoleInfos":[
      {"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true}
    ]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
		Host:              server.URL,
		Username:          "user",
		Password:          "pass",
		NetworkID:         "network-1",
		PlanPath:          planPath,
		APIPrefix:         "/api",
		AllowRemovals:     true,
		MaxRemovals:       1,
		MaxRemovalPercent: 49,
	})
	if err == nil || !strings.Contains(err.Error(), "50.00%") {
		t.Fatalf("expected removal percentage block, got %v", err)
	}
	if patched {
		t.Fatal("removal above percentage limit reached PATCH")
	}
}

func TestApplyPlanRequiresBothRemovalBounds(t *testing.T) {
	tests := []struct {
		name       string
		maxCount   int
		maxPercent float64
	}{
		{name: "neither"},
		{name: "count only", maxCount: 1},
		{name: "percentage only", maxPercent: 100},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patched := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
					_, _ = w.Write([]byte(`[{"type":"AWS","name":"prod","assumeRoleInfos":[
						{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true},
						{"accountId":"222222222222","roleArn":"arn:aws:iam::222222222222:role/ForwardRole","enabled":true}
					]}]`))
				case r.Method == http.MethodPatch:
					patched = true
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			planPath := filepath.Join(t.TempDir(), "payload.json")
			if err := os.WriteFile(planPath, []byte(`{"prod":{"type":"AWS","name":"prod","assumeRoleInfos":[
				{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true}
			]}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
				Host:              server.URL,
				Username:          "user",
				Password:          "pass",
				NetworkID:         "network-1",
				PlanPath:          planPath,
				APIPrefix:         "/api",
				AllowRemovals:     true,
				MaxRemovals:       test.maxCount,
				MaxRemovalPercent: test.maxPercent,
			})
			if err == nil || !strings.Contains(err.Error(), "require both") {
				t.Fatalf("expected explicit bounds block, got %v", err)
			}
			if patched {
				t.Fatal("removal without both bounds reached PATCH")
			}
		})
	}
}

func TestApplyPlanBlocksConcurrentSetupChange(t *testing.T) {
	getCount := 0
	patched := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			getCount++
			enabled := "true"
			if getCount > 1 {
				enabled = "false"
			}
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"prod","assumeRoleInfos":[
				{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":` + enabled + `}
			]}]`))
		case r.Method == http.MethodPatch:
			patched = true
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(planPath, []byte(`{"prod":{"type":"AWS","name":"prod","assumeRoleInfos":[
		{"accountId":"111111111111","roleArn":"arn:aws:iam::111111111111:role/ForwardRole","enabled":true},
		{"accountId":"222222222222","roleArn":"arn:aws:iam::222222222222:role/ForwardRole","enabled":true}
	]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ApplyPlan(context.Background(), ApplyPlanConfig{
		Host:      server.URL,
		Username:  "user",
		Password:  "pass",
		NetworkID: "network-1",
		PlanPath:  planPath,
		APIPrefix: "/api",
	})
	if err == nil || !strings.Contains(err.Error(), "changed after planning") {
		t.Fatalf("expected concurrent-change block, got %v", err)
	}
	if patched {
		t.Fatal("concurrent setup change reached PATCH")
	}
}
