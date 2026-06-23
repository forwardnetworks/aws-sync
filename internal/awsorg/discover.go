package awsorg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
)

type Config struct {
	Profile          string
	Region           string
	IncludeSuspended bool
}

type Result struct {
	OrganizationID      string    `json:"organization_id,omitempty"`
	ManagementAccountID string    `json:"management_account_id,omitempty"`
	Accounts            []Account `json:"accounts"`
	SkippedAccountCount int       `json:"skipped_account_count,omitempty"`
}

type Account struct {
	ID        string   `json:"account_id"`
	Name      string   `json:"account_name,omitempty"`
	Email     string   `json:"email,omitempty"`
	State     string   `json:"state,omitempty"`
	Status    string   `json:"status,omitempty"`
	ParentIDs []string `json:"parent_ids,omitempty"`
}

func Discover(ctx context.Context, cfg Config) (*Result, error) {
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	loadOptions := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile := strings.TrimSpace(cfg.Profile); profile != "" {
		loadOptions = append(loadOptions, config.WithSharedConfigProfile(profile))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS credentials/config: %w", err)
	}
	client := organizations.NewFromConfig(awsCfg)
	return DiscoverWithClient(ctx, client, cfg.IncludeSuspended)
}

type Client interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListParents(context.Context, *organizations.ListParentsInput, ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
}

func DiscoverWithClient(ctx context.Context, client Client, includeSuspended bool) (*Result, error) {
	result := &Result{}
	orgOutput, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return nil, organizationsAccessError("describe AWS organization", err)
	}
	if orgOutput.Organization != nil {
		result.OrganizationID = aws.ToString(orgOutput.Organization.Id)
		result.ManagementAccountID = aws.ToString(orgOutput.Organization.MasterAccountId)
	}
	if result.OrganizationID == "" {
		return nil, fmt.Errorf("describe AWS organization: response did not include organization id")
	}

	pager := organizations.NewListAccountsPaginator(client, &organizations.ListAccountsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, organizationsAccessError("list AWS organization accounts", err)
		}
		for _, awsAccount := range page.Accounts {
			account := accountFromAWS(awsAccount)
			if account.ID == "" {
				continue
			}
			if !includeSuspended && !accountActive(account) {
				result.SkippedAccountCount++
				continue
			}
			parents, err := parentIDs(ctx, client, account.ID)
			if err != nil {
				return nil, err
			}
			account.ParentIDs = parents
			result.Accounts = append(result.Accounts, account)
		}
	}
	return result, nil
}

func accountFromAWS(account orgtypes.Account) Account {
	return Account{
		ID:     aws.ToString(account.Id),
		Name:   aws.ToString(account.Name),
		Email:  aws.ToString(account.Email),
		State:  string(account.State),
		Status: string(account.Status),
	}
}

func accountActive(account Account) bool {
	state := strings.TrimSpace(account.State)
	if state != "" {
		return state == string(orgtypes.AccountStateActive)
	}
	return strings.TrimSpace(account.Status) == string(orgtypes.AccountStatusActive)
}

func parentIDs(ctx context.Context, client Client, accountID string) ([]string, error) {
	pager := organizations.NewListParentsPaginator(client, &organizations.ListParentsInput{
		ChildId: aws.String(accountID),
	})
	var parents []string
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, organizationsAccessError(fmt.Sprintf("list AWS organization parents for account %s", accountID), err)
		}
		for _, parent := range page.Parents {
			if id := aws.ToString(parent.Id); id != "" {
				parents = append(parents, id)
			}
		}
	}
	return parents, nil
}

func organizationsAccessError(action string, err error) error {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return fmt.Errorf("%s: %w", action, err)
	}
	code := apiErr.ErrorCode()
	message := strings.TrimSpace(apiErr.ErrorMessage())
	switch code {
	case "AccessDeniedException", "AWSOrganizationsNotInUseException", "AccessDenied", "UnrecognizedClientException":
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("%s: AWS Organizations access check failed (%s): %s; use credentials from the management account or a delegated administrator with organizations:DescribeOrganization, organizations:ListAccounts, and organizations:ListParents", action, code, message)
	default:
		return fmt.Errorf("%s: %w", action, err)
	}
}
