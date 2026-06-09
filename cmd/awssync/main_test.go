package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
