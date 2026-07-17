package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestChangeExternalIDSetsAndClearsWithoutNQE(t *testing.T) {
	stored := api.CloudAccount{
		Type: "AWS",
		Name: "setup-a",
		Regions: map[string]api.RegionMeta{
			"us-east-1": {TestInstant: 123},
		},
		AssumeRoleInfos: []api.AssumeRoleInfo{{
			AccountID:   "111",
			AccountName: "acct-a",
			RoleArn:     "arn:aws:iam::111:role/ForwardRole",
			Enabled:     true,
		}, {
			AccountID:   "222",
			AccountName: "failed-account",
			ErrorMsg:    "role is not configured",
			Enabled:     false,
		}},
	}
	patchCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]api.CloudAccount{stored})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read patch: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatalf("decode patch fields: %v", err)
			}
			if len(fields) != 2 || fields["type"] == nil || fields["assumeRoleInfos"] == nil {
				t.Fatalf("external ID PATCH changed unrelated fields: %s", string(data))
			}
			var payload api.PatchPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatalf("decode patch: %v", err)
			}
			stored.AssumeRoleInfos = payload.AssumeRoleInfos
			patchCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	base := ExternalIDConfig{
		Host:      server.URL,
		Username:  "alice",
		Password:  "secret",
		NetworkID: "network-1",
		SetupID:   "setup-a",
		APIPrefix: "/api",
		Insecure:  true,
		Apply:     true,
	}
	setConfig := base
	setConfig.ExternalID = "customer-value"
	setConfig.Output = filepath.Join(dir, "set.json")
	setSummary, err := ChangeExternalID(context.Background(), setConfig)
	if err != nil {
		t.Fatalf("set ChangeExternalID() error = %v", err)
	}
	if !setSummary.Patched || setSummary.PreviousExternalIDConfigured || !setSummary.TargetExternalIDConfigured {
		t.Fatalf("unexpected set summary: %#v", setSummary)
	}
	if patchCount != 1 || stored.AssumeRoleInfos[0].ExternalID != "customer-value" || stored.AssumeRoleInfos[1].ExternalID != "customer-value" {
		t.Fatalf("expected set PATCH: count=%d stored=%#v", patchCount, stored.AssumeRoleInfos)
	}
	if stored.AssumeRoleInfos[1].ErrorMsg != "role is not configured" {
		t.Fatalf("expected account error to be preserved: %#v", stored.AssumeRoleInfos[1])
	}

	clearConfig := base
	clearConfig.Clear = true
	clearConfig.Output = filepath.Join(dir, "clear.json")
	clearSummary, err := ChangeExternalID(context.Background(), clearConfig)
	if err != nil {
		t.Fatalf("clear ChangeExternalID() error = %v", err)
	}
	if !clearSummary.Patched || !clearSummary.PreviousExternalIDConfigured || clearSummary.TargetExternalIDConfigured {
		t.Fatalf("unexpected clear summary: %#v", clearSummary)
	}
	if patchCount != 2 || stored.AssumeRoleInfos[0].ExternalID != "" || stored.AssumeRoleInfos[1].ExternalID != "" {
		t.Fatalf("expected clear PATCH: count=%d stored=%#v", patchCount, stored.AssumeRoleInfos)
	}
}

func TestChangeExternalIDRequiresOneAction(t *testing.T) {
	for _, cfg := range []ExternalIDConfig{
		{SetupID: "setup-a"},
		{SetupID: "setup-a", ExternalID: "value", Clear: true},
	} {
		if _, err := ChangeExternalID(context.Background(), cfg); err == nil {
			t.Fatalf("expected action validation error for %#v", cfg)
		}
	}
}
