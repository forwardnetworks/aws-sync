package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
	"github.com/forwardnetworks/aws-sync/internal/app"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestRootCommandIncludesBuildMetadataInVersion(t *testing.T) {
	cmd := newRootCommand()
	want := fmt.Sprintf("%s (commit %s, built %s)", version, commit, buildDate)
	if cmd.Version != want {
		t.Fatalf("unexpected version %q; want %q", cmd.Version, want)
	}
}

func TestRootCommandHonorsLocalSnapshotAndOutputFlags(t *testing.T) {
	var seenNQEQuery string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			seenNQEQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":false}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","externalId":"Org:99","enabled":true}]}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "payload.json")
	manualOutputPath := filepath.Join(t.TempDir(), "manual-payload.json")
	stdout := captureStdout(t, func() {
		cmd := newRootCommand()
		cmd.SetArgs([]string{
			"--host", server.URL,
			"--username", "alice",
			"--password", "secret",
			"--network-id", "network-1",
			"--snapshot-id", "snapshot-1",
			"--output", outputPath,
			"--manual-output", manualOutputPath,
			"--json",
			"--insecure",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	var summary map[string]any
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, stdout)
	}
	if summary["snapshot_id"] != "snapshot-1" {
		t.Fatalf("expected snapshot_id in summary, got %#v", summary)
	}
	if summary["output"] != outputPath {
		t.Fatalf("expected output path %q, got %#v", outputPath, summary["output"])
	}
	if summary["manual_output"] != manualOutputPath {
		t.Fatalf("expected manual_output path %q, got %#v", manualOutputPath, summary["manual_output"])
	}
	if seenNQEQuery != "networkId=network-1&snapshotId=snapshot-1" &&
		seenNQEQuery != "snapshotId=snapshot-1&networkId=network-1" {
		t.Fatalf("unexpected NQE query string %q", seenNQEQuery)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected payload at output path: %v", err)
	}
	if _, err := os.Stat(manualOutputPath); err != nil {
		t.Fatalf("expected manual payload at output path: %v", err)
	}
	if _, err := os.Stat("aws_sync_payload.json"); err == nil {
		t.Fatal("unexpected default payload file was created")
	}
}

func TestApplyPlanCommandHonorsLocalYesFlag(t *testing.T) {
	patched := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"setup-a","assumeRoleInfos":[]}]`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
			patched = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	planPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(planPath, []byte(`{"setup-a":{"type":"AWS","name":"setup-a","regionToProxyServerId":{},"assumeRoleInfos":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		cmd := newRootCommand()
		cmd.SetArgs([]string{
			"apply-plan",
			"--host", server.URL,
			"--username", "alice",
			"--password", "secret",
			"--network-id", "network-1",
			"--plan", planPath,
			"--yes",
			"--json",
			"--insecure",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !patched {
		t.Fatal("apply-plan --yes did not reach PATCH")
	}
}

func TestSafeSyncRunsPreflightPreviewAndAdditiveApply(t *testing.T) {
	enabled := false
	patched := false
	processedAt := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/snapshots/latestProcessed":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id":"snapshot-1","state":"PROCESSED","processedAt":%q}`, processedAt)
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items":[{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Cloud Account Name":"acct-a","Collected?":false}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(
				w,
				`[{"type":"AWS","name":"setup-a","regions":{"us-east-1":{"testInstant":123}},"assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":%t}]}]`,
				enabled,
			)
		case r.Method == http.MethodPatch && r.URL.Path == "/api/networks/network-1/cloudAccounts/setup-a":
			var payload api.PatchPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode patch payload: %v", err)
			}
			if len(payload.AssumeRoleInfos) != 1 || !payload.AssumeRoleInfos[0].Enabled {
				t.Fatalf("safe-sync payload did not re-enable account: %#v", payload)
			}
			enabled = true
			patched = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "safe-sync.json")
	stdout := captureStdout(t, func() {
		cmd := newRootCommand()
		cmd.SetArgs([]string{
			"safe-sync",
			"--host", server.URL,
			"--username", "alice",
			"--password", "secret",
			"--network-id", "network-1",
			"--setup-id", "setup-a",
			"--output", output,
			"--yes",
			"--insecure",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !patched || !enabled {
		t.Fatal("safe-sync did not apply the additive re-enable")
	}
	for _, expected := range []string{
		"Safe sync preview",
		"additive only",
		"add=0 reenable=1 remove=0",
		"Safe sync complete",
		"rollback",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("safe-sync output missing %q:\n%s", expected, stdout)
		}
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("safe-sync payload missing: %v", err)
	}
}

func TestSafeSyncHandlesMultipleSetups(t *testing.T) {
	patched := map[string]bool{}
	processedAt := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/snapshots/latestProcessed":
			_, _ = fmt.Fprintf(w, `{"id":"snapshot-1","state":"PROCESSED","processedAt":%q}`, processedAt)
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			_, _ = w.Write([]byte(`{"items":[
				{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Collected?":false},
				{"Cloud Setup ID":"setup-b","Cloud Account ID":"222","Collected?":false}
			]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[
				{"type":"AWS","name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":false}]},
				{"type":"AWS","name":"setup-b","assumeRoleInfos":[{"roleArn":"arn:aws:iam::222:role/ForwardRole","enabled":false}]}
			]`))
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/networks/network-1/cloudAccounts/"):
			setupID := strings.TrimPrefix(r.URL.Path, "/api/networks/network-1/cloudAccounts/")
			patched[setupID] = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	output := filepath.Join(t.TempDir(), "safe-sync.json")
	stdout := captureStdout(t, func() {
		cmd := newRootCommand()
		cmd.SetArgs([]string{
			"safe-sync",
			"--host", server.URL,
			"--username", "alice",
			"--password", "secret",
			"--network-id", "network-1",
			"--setup-id", "setup-a",
			"--setup-id", "setup-b",
			"--output", output,
			"--yes",
			"--insecure",
		})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !patched["setup-a"] || !patched["setup-b"] || len(patched) != 2 {
		t.Fatalf("safe-sync did not isolate and patch both selected setups: %#v", patched)
	}
	for _, setupID := range []string{"setup-a", "setup-b"} {
		if !strings.Contains(stdout, setupID) {
			t.Fatalf("safe-sync preview missing %s:\n%s", setupID, stdout)
		}
	}
}

func TestSafeSyncRequiresConfirmationOutsideAutomation(t *testing.T) {
	patched := false
	processedAt := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/snapshots/latestProcessed":
			_, _ = fmt.Fprintf(w, `{"id":"snapshot-1","state":"PROCESSED","processedAt":%q}`, processedAt)
		case r.Method == http.MethodPost && r.URL.Path == "/api/nqe":
			_, _ = w.Write([]byte(`{"items":[{"Cloud Setup ID":"setup-a","Cloud Account ID":"111","Collected?":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodPatch:
			patched = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var executeErr error
	captureStdout(t, func() {
		cmd := newRootCommand()
		cmd.SetArgs([]string{
			"safe-sync",
			"--host", server.URL,
			"--username", "alice",
			"--password", "secret",
			"--network-id", "network-1",
			"--setup-id", "setup-a",
			"--insecure",
		})
		executeErr = cmd.Execute()
	})
	if executeErr == nil || !strings.Contains(executeErr.Error(), "requires an interactive confirmation") {
		t.Fatalf("unexpected error: %v", executeErr)
	}
	if patched {
		t.Fatal("safe-sync without confirmation reached PATCH")
	}
}

func TestSafeSyncStopsWhenPreflightIsNotReady(t *testing.T) {
	patched := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/cloudAccounts":
			_, _ = w.Write([]byte(`[{"type":"AWS","name":"setup-a","assumeRoleInfos":[{"roleArn":"arn:aws:iam::111:role/ForwardRole","enabled":true}]}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/networks/network-1/snapshots/latestProcessed":
			_, _ = w.Write([]byte(`{"id":"stale","state":"PROCESSED","processedAt":"2020-01-01T00:00:00Z"}`))
		case r.Method == http.MethodPatch:
			patched = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cmd := newRootCommand()
	cmd.SetArgs([]string{
		"safe-sync",
		"--host", server.URL,
		"--username", "alice",
		"--password", "secret",
		"--network-id", "network-1",
		"--setup-id", "setup-a",
		"--yes",
		"--insecure",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "preflight is not ready") || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("unexpected error: %v", err)
	}
	if patched {
		t.Fatal("failed safe-sync preflight reached PATCH")
	}
}

func TestSafeSyncHelpHidesExpertMutationFlags(t *testing.T) {
	safeSync, _, err := newRootCommand().Find([]string{"safe-sync"})
	if err != nil {
		t.Fatalf("find safe-sync: %v", err)
	}
	if !strings.Contains(safeSync.Short, "additive-only") {
		t.Fatalf("safe-sync description does not explain its mode: %q", safeSync.Short)
	}
	for _, name := range []string{"network-id", "setup-id"} {
		flag := safeSync.Flags().Lookup(name)
		if flag == nil || flag.Hidden {
			t.Fatalf("safe-sync does not expose --%s", name)
		}
	}
	for _, name := range []string{"prune-missing", "allow-removals", "max-removals"} {
		if flag := safeSync.Flags().Lookup(name); flag != nil {
			t.Fatalf("safe-sync unexpectedly defines expert flag --%s", name)
		}
	}
	for _, name := range []string{"yes", "output"} {
		flag := safeSync.Flags().Lookup(name)
		if flag == nil || !flag.Hidden {
			t.Fatalf("safe-sync internal flag --%s should be hidden", name)
		}
	}
}

func TestEmitErrorFormatsNetworkSelectionOnce(t *testing.T) {
	var buf bytes.Buffer
	emitError(&buf, &app.NetworkSelectionError{
		Message: "network ID is required because this user can see multiple networks",
		Count:   3,
		Choices: []app.NetworkChoice{
			{ID: "102", Name: "1-Fiserv-Prod"},
			{ID: "2059", Name: "AWS-test"},
		},
		Truncated: true,
		UseFlag:   "--network-id NETWORK_ID",
		Examples:  []string{"--network-id 2059"},
	})

	output := buf.String()
	if strings.Count(output, "network ID is required") != 1 {
		t.Fatalf("expected one error message, got:\n%s", output)
	}
	for _, unexpected := range []string{"Usage:", "Flags:", "network_selection_required", "\"choices\""} {
		if strings.Contains(output, unexpected) {
			t.Fatalf("unexpected %q in output:\n%s", unexpected, output)
		}
	}
	for _, expected := range []string{"showing 2 of 3", "2059  AWS-test", "Use --network-id NETWORK_ID", "Examples: --network-id 2059"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in output:\n%s", expected, output)
		}
	}
}

func TestEmitErrorFormatsSetupSelection(t *testing.T) {
	var buf bytes.Buffer
	emitError(&buf, &setupSelectionError{
		Message:   "setup IDs are required because this user can see multiple AWS setups in this network",
		Count:     3,
		Choices:   []string{"setup-a", "setup-b", "setup-c"},
		Truncated: false,
		UseFlag:   "--network-id 2059 --setup-id <SETUP_ID>",
		Examples:  []string{"--setup-id setup-b", "--setup-id setup-c"},
	})

	output := buf.String()
	if strings.Count(output, "setup IDs are required") != 1 {
		t.Fatalf("expected one error message, got:\n%s", output)
	}
	for _, expected := range []string{"Visible AWS setups (3)", "setup-a", "Use --network-id 2059 --setup-id <SETUP_ID>", "Examples: --setup-id setup-b, --setup-id setup-c"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in output:\n%s", expected, output)
		}
	}
}

func TestSelectNetworkIDAcceptsNumber(t *testing.T) {
	choices := []app.NetworkChoice{
		{ID: "102", Name: "1-Fiserv-Prod"},
		{ID: "2059", Name: "AWS-test"},
	}
	var stderr bytes.Buffer
	selected, err := selectNetworkID(choices, strings.NewReader("2\n"), &stderr)
	if err != nil {
		t.Fatalf("selectNetworkID() error = %v", err)
	}
	if selected != "2059" {
		t.Fatalf("expected network 2059, got %q", selected)
	}
	if !strings.Contains(stderr.String(), "Enter number or network ID:") {
		t.Fatalf("missing prompt in stderr:\n%s", stderr.String())
	}
}

func TestSelectNetworkIDAcceptsID(t *testing.T) {
	choices := []app.NetworkChoice{
		{ID: "102", Name: "1-Fiserv-Prod"},
		{ID: "2059", Name: "AWS-test"},
	}
	selected, err := selectNetworkID(choices, strings.NewReader("2059\n"), io.Discard)
	if err != nil {
		t.Fatalf("selectNetworkID() error = %v", err)
	}
	if selected != "2059" {
		t.Fatalf("expected network 2059, got %q", selected)
	}
}

func TestSelectNetworkIDRejectsBadInput(t *testing.T) {
	choices := []app.NetworkChoice{
		{ID: "102", Name: "1-Fiserv-Prod"},
		{ID: "2059", Name: "AWS-test"},
	}
	if _, err := selectNetworkID(choices, strings.NewReader("9999\n"), io.Discard); err == nil {
		t.Fatal("expected invalid selection error")
	}
}

func TestResolveOutputFormat(t *testing.T) {
	v := viper.New()
	v.Set("format", "human")
	cmd := &cobra.Command{}
	format, err := resolveOutputFormat(cmd, v)
	if err != nil {
		t.Fatalf("resolveOutputFormat() error = %v", err)
	}
	if format != "human" {
		t.Fatalf("expected human, got %q", format)
	}
}

func TestResolveOutputFormatDefaultsToHuman(t *testing.T) {
	v := viper.New()
	cmd := &cobra.Command{}
	format, err := resolveOutputFormat(cmd, v)
	if err != nil {
		t.Fatalf("resolveOutputFormat() error = %v", err)
	}
	if format != "human" {
		t.Fatalf("expected human default, got %q", format)
	}
}

func TestResolveOutputFormatJSONAlias(t *testing.T) {
	v := viper.New()
	v.Set("format", "human")
	v.Set("json", true)
	cmd := &cobra.Command{}
	format, err := resolveOutputFormat(cmd, v)
	if err != nil {
		t.Fatalf("resolveOutputFormat() error = %v", err)
	}
	if format != "json" {
		t.Fatalf("expected --json to override human, got %q", format)
	}
}

func TestResolveOutputFormatRejectsInvalidValue(t *testing.T) {
	v := viper.New()
	v.Set("format", "yaml")
	cmd := &cobra.Command{}
	if _, err := resolveOutputFormat(cmd, v); err == nil {
		t.Fatal("expected invalid format error")
	}
}

func TestSelectSetupIDsAcceptsNumberAndID(t *testing.T) {
	choices := []string{"alpha", "beta", "zeta"}
	var stderr bytes.Buffer
	selected, err := selectSetupIDs(choices, strings.NewReader("2\n"), &stderr)
	if err != nil {
		t.Fatalf("selectSetupIDs() error = %v", err)
	}
	if len(selected) != 1 || selected[0] != "beta" {
		t.Fatalf("expected [beta], got %#v", selected)
	}
	selected, err = selectSetupIDs(choices, strings.NewReader("zeta\n"), &stderr)
	if err != nil {
		t.Fatalf("selectSetupIDs() error = %v", err)
	}
	if len(selected) != 1 || selected[0] != "zeta" {
		t.Fatalf("expected [zeta], got %#v", selected)
	}
}

func TestSelectSetupIDsIsCaseInsensitive(t *testing.T) {
	choices := []string{"Alpha", "beta", "ZEta"}
	selected, err := selectSetupIDs(choices, strings.NewReader("alpha, zETA\n"), io.Discard)
	if err != nil {
		t.Fatalf("selectSetupIDs() error = %v", err)
	}
	if len(selected) != 2 || selected[0] != "Alpha" || selected[1] != "ZEta" {
		t.Fatalf("expected [Alpha ZEta], got %#v", selected)
	}
}

func TestSelectSetupIDsAcceptsAllAndReturnsAll(t *testing.T) {
	choices := []string{"alpha", "beta"}
	var stderr bytes.Buffer
	selected, err := selectSetupIDs(choices, strings.NewReader("\n"), &stderr)
	if err != nil {
		t.Fatalf("selectSetupIDs() error = %v", err)
	}
	if len(selected) != len(choices) {
		t.Fatalf("expected all setups, got %#v", selected)
	}

	selected, err = selectSetupIDs(choices, strings.NewReader("all\n"), io.Discard)
	if err != nil {
		t.Fatalf("selectSetupIDs() error = %v", err)
	}
	if len(selected) != len(choices) {
		t.Fatalf("expected all setups, got %#v", selected)
	}
}

func TestSetupChoicesFiltersAWSAndSorts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`[
			{"name":"zeta","type":"AWS"},
			{"name":"alpha","type":"aws"},
			{"name":"dup","type":"AWS"},
			{"name":"dup","type":"AWS"},
			{"name":"azure","type":"AZURE"}
		]`))
	}))
	defer server.Close()

	client, err := api.NewClient(
		server.URL,
		"/api",
		"alice",
		"secret",
		true,
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	choices, err := setupChoices(context.Background(), client, "network-1")
	if err != nil {
		t.Fatalf("setupChoices() error = %v", err)
	}
	if len(choices) != 3 || choices[0] != "alpha" || choices[1] != "dup" || choices[2] != "zeta" {
		t.Fatalf("unexpected setup choices: %#v", choices)
	}
}

func TestResolveSetupIDsForCLINonInteractiveRequiresSelectionWhenMultipleSetups(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`[
			{"name":"setup-a","type":"AWS"},
			{"name":"setup-b","type":"AWS"}
		]`))
	}))
	defer server.Close()

	v := viper.New()
	v.Set("host", server.URL)
	v.Set("api-prefix", "/api")
	v.Set("username", "alice")
	v.Set("insecure", true)
	v.Set("timeout", 2*time.Second)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.WriteString("unused")

	err = nil
	var setupErr *setupSelectionError
	_, err = resolveSetupIDsForCLI(context.Background(), v, "secret", "network-1", nil, r, io.Discard)
	if err == nil {
		t.Fatalf("expected setup-id prompt/selection error")
	}
	if !errors.As(err, &setupErr) {
		t.Fatalf("expected *setupSelectionError, got %T: %v", err, err)
	}
	if got, want := setupErr.Count, 2; got != want {
		t.Fatalf("expected count %d, got %d", want, got)
	}
	if got, want := setupErr.UseFlag, "--network-id network-1 --setup-id SETUP_ID"; got != want {
		t.Fatalf("expected use flag %q, got %q", want, got)
	}
	if setupErr.Truncated {
		t.Fatalf("expected truncation false for two choices")
	}
}

func TestResolveSetupIDsForCLIResolvesProvidedIDsCaseInsensitive(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`[
			{"name":"Alpha-Prod","type":"AWS"},
			{"name":"beta-Sandbox","type":"AWS"}
		]`))
	}))
	defer server.Close()

	v := viper.New()
	v.Set("host", server.URL)
	v.Set("api-prefix", "/api")
	v.Set("username", "alice")
	v.Set("insecure", true)
	v.Set("timeout", 2*time.Second)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.WriteString("unused")

	setupIDs, err := resolveSetupIDsForCLI(context.Background(), v, "secret", "network-1", []string{"alpha-prod", "BETA-SANDBOX"}, r, io.Discard)
	if err != nil {
		t.Fatalf("resolveSetupIDsForCLI() error = %v", err)
	}
	if len(setupIDs) != 2 || setupIDs[0] != "Alpha-Prod" || setupIDs[1] != "beta-Sandbox" {
		t.Fatalf("expected canonical setup IDs, got %#v", setupIDs)
	}
}

func TestResolveSetupIDsForCLIFailsUnknownSetupID(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`[
			{"name":"Alpha-Prod","type":"AWS"},
			{"name":"beta-Sandbox","type":"AWS"}
		]`))
	}))
	defer server.Close()

	v := viper.New()
	v.Set("host", server.URL)
	v.Set("api-prefix", "/api")
	v.Set("username", "alice")
	v.Set("insecure", true)
	v.Set("timeout", 2*time.Second)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.WriteString("unused")

	_, err = resolveSetupIDsForCLI(context.Background(), v, "secret", "network-1", []string{"missing-setup"}, r, io.Discard)
	var setupErr *setupSelectionError
	if err == nil {
		t.Fatal("expected setup-id validation error")
	}
	if !errors.As(err, &setupErr) {
		t.Fatalf("expected *setupSelectionError, got %T: %v", err, err)
	}
	if !strings.Contains(setupErr.Message, "missing-setup") {
		t.Fatalf("expected missing setup ID in message, got %q", setupErr.Message)
	}
}

func TestResolveSetupIDsForCLINonInteractiveAutoSelectsSingle(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/networks/network-1/cloudAccounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"only-setup","type":"AWS"}]`))
	}))
	defer server.Close()

	v := viper.New()
	v.Set("host", server.URL)
	v.Set("api-prefix", "/api")
	v.Set("username", "alice")
	v.Set("insecure", true)
	v.Set("timeout", 2*time.Second)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, _ = w.WriteString("unused")

	setupIDs, err := resolveSetupIDsForCLI(context.Background(), v, "secret", "network-1", nil, r, io.Discard)
	if err != nil {
		t.Fatalf("resolveSetupIDsForCLI() error = %v", err)
	}
	if len(setupIDs) != 1 || setupIDs[0] != "only-setup" {
		t.Fatalf("unexpected setup IDs %#v", setupIDs)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = original
	})
	fn()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(data)
}
