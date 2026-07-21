package awsorg

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
)

type fakeOrganizationsClient struct {
	describeErr error
	listErr     error
	parentErr   error
	accounts    []orgtypes.Account
	parents     map[string][]orgtypes.Parent
}

func (f fakeOrganizationsClient) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &organizations.DescribeOrganizationOutput{
		Organization: &orgtypes.Organization{
			Id:              aws.String("o-example"),
			Arn:             aws.String("arn:aws-us-gov:organizations::111111111111:organization/o-example"),
			MasterAccountId: aws.String("111111111111"),
		},
	}, nil
}

func (f fakeOrganizationsClient) ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &organizations.ListAccountsOutput{Accounts: f.accounts}, nil
}

func (f fakeOrganizationsClient) ListParents(_ context.Context, input *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	if f.parentErr != nil {
		return nil, f.parentErr
	}
	return &organizations.ListParentsOutput{Parents: f.parents[aws.ToString(input.ChildId)]}, nil
}

func TestDiscoverWithClientChecksOrganizationAndParents(t *testing.T) {
	client := fakeOrganizationsClient{
		accounts: []orgtypes.Account{
			{Id: aws.String("111111111111"), Name: aws.String("management"), State: orgtypes.AccountStateActive},
			{Id: aws.String("222222222222"), Name: aws.String("app"), State: orgtypes.AccountStateActive},
			{Id: aws.String("333333333333"), Name: aws.String("suspended"), State: orgtypes.AccountStateSuspended},
		},
		parents: map[string][]orgtypes.Parent{
			"111111111111": {{Id: aws.String("r-root")}},
			"222222222222": {{Id: aws.String("ou-root-apps")}},
		},
	}

	result, err := DiscoverWithClient(context.Background(), client, false)
	if err != nil {
		t.Fatalf("DiscoverWithClient() error = %v", err)
	}
	if result.OrganizationID != "o-example" || result.ManagementAccountID != "111111111111" || result.Partition != "aws-us-gov" {
		t.Fatalf("unexpected organization metadata: %#v", result)
	}
	if len(result.Accounts) != 2 || result.SkippedAccountCount != 1 {
		t.Fatalf("unexpected account filtering: %#v", result)
	}
	if got := result.Accounts[1].ParentIDs; len(got) != 1 || got[0] != "ou-root-apps" {
		t.Fatalf("expected parent IDs from ListParents, got %#v", got)
	}
}

func TestDiscoverWithClientExplainsOrganizationsAccessDenied(t *testing.T) {
	client := fakeOrganizationsClient{
		describeErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"},
	}

	_, err := DiscoverWithClient(context.Background(), client, false)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{
		"AWS Organizations access check failed",
		"organizations:DescribeOrganization",
		"organizations:ListAccounts",
		"organizations:ListParents",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}
}
