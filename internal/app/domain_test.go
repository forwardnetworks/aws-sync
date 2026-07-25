package app

import (
	"testing"
)

func TestNewAccountIDRejectsMalformedAndTrimsWhitespace(t *testing.T) {
	got, err := NewAccountID(" 111111111111 ")
	if err != nil {
		t.Fatalf("NewAccountID() error = %v", err)
	}
	if got.String() != "111111111111" {
		t.Fatalf("AccountID = %q", got)
	}

	tests := []string{"", "123", "12345678901", "1234567890123", "123456789abc"}
	for _, value := range tests {
		if _, err := NewAccountID(value); err == nil {
			t.Fatalf("expected malformed account-id error for %q", value)
		}
	}
}

func TestNewSetupIDRejectsBlankAndTrims(t *testing.T) {
	got, err := NewSetupID("  setup-a ")
	if err != nil {
		t.Fatalf("NewSetupID() error = %v", err)
	}
	if got != "setup-a" {
		t.Fatalf("SetupID = %q", got)
	}

	if _, err := NewSetupID("  "); err == nil {
		t.Fatal("expected blank setup-id error")
	}
}

func TestNewPartitionRejectsInvalid(t *testing.T) {
	if _, err := NewPartition("aws-bad"); err == nil {
		t.Fatal("expected partition error")
	}
}

func TestParseRoleARNTrimsAndValidates(t *testing.T) {
	role, err := ParseRoleARN(" arn:aws:iam::111111111111:role/ForwardRole ")
	if err != nil {
		t.Fatalf("ParseRoleARN() error = %v", err)
	}
	if role.String() == "" {
		t.Fatal("role string is empty")
	}
	if role.AccountID().String() != "111111111111" {
		t.Fatalf("role account = %q", role.AccountID())
	}
	if role.RoleName() != "ForwardRole" {
		t.Fatalf("role name = %q", role.RoleName())
	}
}
