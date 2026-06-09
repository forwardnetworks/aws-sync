package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusNotFound)
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
