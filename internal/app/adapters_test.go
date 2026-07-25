package app

import (
	"strings"
	"testing"

	"github.com/forwardnetworks/aws-sync/internal/api"
)

func TestParseNQESnapshotFromMapsTrimsWhitespace(t *testing.T) {
	items := []map[string]any{
		{
			"Cloud Setup ID":          "  setup-a  ",
			"Cloud Account ID":        " 111111111111 ",
			"Cloud Account Name":      " acct-a ",
			"Collected?":              " true ",
			"Account Lifecycle":       " Active ",
			"Organizational Unit IDs": []string{"ou-root"},
		},
	}
	snapshot, err := parseNQESnapshotFromMaps(items)
	if err != nil {
		t.Fatalf("parseNQESnapshotFromMaps() error = %v", err)
	}
	if got := snapshot.DiscoveredAccounts[0].AccountID.String(); got != "111111111111" {
		t.Fatalf("account id = %q", got)
	}
	if got := snapshot.DiscoveredAccounts[0].AccountName; got != "acct-a" {
		t.Fatalf("account name = %q", got)
	}
	if got := snapshot.DiscoveredAccounts[0].Lifecycle; got != AccountLifecycleActive {
		t.Fatalf("lifecycle = %q", got)
	}
	if !snapshot.DiscoveredAccounts[0].Collected {
		t.Fatalf("expected collected flag true")
	}
}

func TestParseNQESnapshotFromMapsRejectsNumericAccountID(t *testing.T) {
	items := []map[string]any{{
		"Cloud Setup ID":     "setup-a",
		"Cloud Account ID":   111111111111,
		"Cloud Account Name": "acct-a",
	}}
	if _, err := parseNQESnapshotFromMaps(items); err == nil || !strings.Contains(err.Error(), "non-string Cloud Account ID") {
		t.Fatalf("expected numeric-ID type error, got %v", err)
	}
}

func TestParseNQESnapshotFromMapsRejectsDuplicateAccountAcrossRows(t *testing.T) {
	items := []map[string]any{
		{"Cloud Setup ID": "setup-a", "Cloud Account ID": "111111111111", "Cloud Account Name": "acct-a"},
		{"Cloud Setup ID": "setup-b", "Cloud Account ID": "111111111111", "Cloud Account Name": "acct-b"},
	}
	if _, err := parseNQESnapshotFromMaps(items); err == nil || !strings.Contains(err.Error(), "already appears in setup setup-a") {
		t.Fatalf("expected cross-setup duplicate error, got %v", err)
	}
}

func TestParseCloudSetupAccountInfoRejectsRoleARNAccountMismatch(t *testing.T) {
	_, _, err := parseCloudSetupAccountInfo(api.AssumeRoleInfo{
		AccountID: "111111111111",
		RoleArn:   "arn:aws:iam::222222222222:role/ForwardRole",
	}, SetupID("setup-a"), 3)
	if err == nil || !strings.Contains(err.Error(), "disagrees with role ARN account") {
		t.Fatalf("expected account/ARN mismatch error, got %v", err)
	}
}

func TestAdaptCloudAccountsBySetupIDRejectsDuplicateSetupID(t *testing.T) {
	_, err := adaptCloudAccountsBySetupID([]api.CloudAccount{
		{Name: "setup-a", AssumeRoleInfos: []api.AssumeRoleInfo{{AccountID: "111111111111", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole"}}},
		{Name: "setup-a", AssumeRoleInfos: []api.AssumeRoleInfo{{AccountID: "222222222222", RoleArn: "arn:aws:iam::222222222222:role/ForwardRole"}}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "forward setup list contains duplicate setup-id setup-a") {
		t.Fatalf("expected duplicate setup error, got %v", err)
	}
}

func TestAdaptCloudAccountsBySetupIDAcceptsWhitespaceAccountIDs(t *testing.T) {
	accounts, err := adaptCloudAccountsBySetupID([]api.CloudAccount{{
		Name:            " setup-a ",
		AssumeRoleInfos: []api.AssumeRoleInfo{{AccountID: " 111111111111 ", RoleArn: "arn:aws:iam::111111111111:role/ForwardRole"}},
	}}, nil)
	if err != nil {
		t.Fatalf("adaptCloudAccountsBySetupID() error = %v", err)
	}
	if _, ok := accounts[SetupID("setup-a")]; !ok {
		t.Fatalf("expected normalized setup-id key")
	}
}
