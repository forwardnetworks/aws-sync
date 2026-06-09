package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreflightReportsSetupSpecificOrgEvidenceFailures(t *testing.T) {
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
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	summary, err := Preflight(context.Background(), Config{
		Host:               server.URL,
		Username:           "alice",
		Password:           "secret",
		NetworkID:          "network-1",
		SnapshotID:         "snapshot-1",
		QueryID:            "custom-query",
		APIPrefix:          "/api",
		Insecure:           true,
		SetupIDs:           nil,
		MaxSnapshotAge:     0,
		AllowNoOrgEvidence: false,
	})
	if err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	if summary.Ready {
		t.Fatalf("expected preflight not ready when removals are unsafe")
	}

	var checkStatus, checkMessage string
	for _, check := range summary.Checks {
		if check.Name == "aws_organizations_evidence" {
			checkStatus = check.Status
			checkMessage = check.Message
		}
	}
	if checkStatus != "fail" {
		t.Fatalf("expected aws_organizations_evidence to fail, got status=%q message=%q", checkStatus, checkMessage)
	}
	if !strings.Contains(checkMessage, "setup-b") {
		t.Fatalf("expected failure message to include missing-setup ID, got: %q", checkMessage)
	}
	if !strings.Contains(checkMessage, "--allow-no-org-evidence") {
		t.Fatalf("expected guidance for --allow-no-org-evidence, got: %q", checkMessage)
	}
}

func TestPlansWithoutOrganizationEvidenceSortsSetups(t *testing.T) {
	plan := &patchPlan{
		Setups: []plannedSetup{
			{SetupID: "zeta", DiscoveredCandidateCount: 0, DiscoveredOrgUnitRowCount: 0},
			{SetupID: "alpha", DiscoveredCandidateCount: 1, DiscoveredOrgUnitRowCount: 0},
			{SetupID: "beta", DiscoveredCandidateCount: 0, DiscoveredOrgUnitRowCount: 0},
		},
	}
	missing := plansWithoutOrganizationEvidence(plan)
	want := []string{"beta", "zeta"}
	if len(missing) != len(want) {
		t.Fatalf("expected %d missing setups, got %d (%v)", len(want), len(missing), missing)
	}
	for i, wantID := range want {
		if missing[i] != wantID {
			t.Fatalf("expected missing setup at %d = %s, got %s", i, wantID, missing[i])
		}
	}
}
