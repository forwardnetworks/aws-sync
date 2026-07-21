package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		[]byte(`{"setup-a":{"type":"AWS","name":"setup-a","regionToProxyServerId":{},"assumeRoleInfos":[]}}`),
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
		Host:          server.URL,
		Username:      "user",
		Password:      "pass",
		NetworkID:     "network-1",
		PlanPath:      planPath,
		APIPrefix:     "/api",
		AllowRemovals: true,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot remove GovCloud accounts") {
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
              {"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true},
              {"accountId":"222","roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":true}
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
      {"accountId":"111","roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}
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
		MaxRemovalPercent: 49,
	})
	if err == nil || !strings.Contains(err.Error(), "50.00%") {
		t.Fatalf("expected removal percentage block, got %v", err)
	}
	if patched {
		t.Fatal("removal above percentage limit reached PATCH")
	}
}
