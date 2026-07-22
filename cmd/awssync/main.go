package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/forwardnetworks/aws-sync/internal/api"
	"github.com/forwardnetworks/aws-sync/internal/app"
	"github.com/forwardnetworks/aws-sync/internal/awsorg"
	"github.com/forwardnetworks/aws-sync/internal/monitor"
	"github.com/forwardnetworks/aws-sync/internal/webhook"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		emitError(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	v := viper.New()
	v.SetEnvPrefix("AWSSYNC")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	v.SetDefault("api-prefix", "/api")
	v.SetDefault("format", "json")
	v.SetDefault("timeout", 60*time.Second)
	v.SetDefault("output", "")
	v.SetDefault("wait-for-state", "PROCESSED")
	v.SetDefault("poll-interval", 10*time.Second)

	cmd := &cobra.Command{
		Use:           "awssync",
		Short:         "Sync AWS cloud account setup payloads in Forward Networks",
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version, commit, buildDate),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDForCLI(cmd.Context(), v, password, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			setupIDs, err := resolveSetupIDsForCLI(cmd.Context(), v, password, networkID, flagStringSlice(cmd, v, "setup-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			apply := flagBool(cmd, v, "apply")
			yes := flagBool(cmd, v, "yes")
			if apply && !yes && term.IsTerminal(int(os.Stdin.Fd())) {
				preview := app.Config{
					Host:               v.GetString("host"),
					Username:           v.GetString("username"),
					Password:           password,
					NetworkID:          networkID,
					SnapshotID:         flagString(cmd, v, "snapshot-id"),
					QueryID:            flagString(cmd, v, "query-id"),
					QuerySetupParam:    flagString(cmd, v, "query-setup-param"),
					SetupIDs:           setupIDs,
					Output:             flagString(cmd, v, "output"),
					ManualOutput:       flagString(cmd, v, "manual-output"),
					APIPrefix:          v.GetString("api-prefix"),
					Insecure:           v.GetBool("insecure"),
					Timeout:            v.GetDuration("timeout"),
					AllowRemovals:      flagBool(cmd, v, "allow-removals"),
					MaxRemovals:        flagInt(cmd, v, "max-removals"),
					MaxRemovalPercent:  flagFloat64(cmd, v, "max-removal-percent"),
					AllowNoCandidates:  flagBool(cmd, v, "allow-no-candidates"),
					AllowNoOrgEvidence: flagBool(cmd, v, "allow-no-org-evidence"),
					MaxSnapshotAge:     flagDuration(cmd, v, "max-snapshot-age"),
					ExternalIDFile:     flagString(cmd, v, "external-id-file"),
				}
				previewSummary, err := app.Run(cmd.Context(), preview)
				if err != nil {
					return err
				}
				if err := confirmApplyFromSummary(previewSummary, os.Stdin, os.Stderr); err != nil {
					return err
				}
			} else {
				if err := confirmApply(apply, yes, os.Stdin, os.Stderr); err != nil {
					return err
				}
			}
			cfg := app.Config{
				Host:               v.GetString("host"),
				Username:           v.GetString("username"),
				Password:           password,
				NetworkID:          networkID,
				SnapshotID:         flagString(cmd, v, "snapshot-id"),
				QueryID:            flagString(cmd, v, "query-id"),
				QuerySetupParam:    flagString(cmd, v, "query-setup-param"),
				SetupIDs:           setupIDs,
				Output:             flagString(cmd, v, "output"),
				ManualOutput:       flagString(cmd, v, "manual-output"),
				APIPrefix:          v.GetString("api-prefix"),
				Insecure:           v.GetBool("insecure"),
				Timeout:            v.GetDuration("timeout"),
				Apply:              apply,
				AllowRemovals:      flagBool(cmd, v, "allow-removals"),
				MaxRemovals:        flagInt(cmd, v, "max-removals"),
				MaxRemovalPercent:  flagFloat64(cmd, v, "max-removal-percent"),
				AllowNoCandidates:  flagBool(cmd, v, "allow-no-candidates"),
				AllowNoOrgEvidence: flagBool(cmd, v, "allow-no-org-evidence"),
				MaxSnapshotAge:     flagDuration(cmd, v, "max-snapshot-age"),
				ExternalIDFile:     flagString(cmd, v, "external-id-file"),
			}
			summary, err := app.Run(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}

	bindCommonFlags(v, cmd.PersistentFlags())
	bindNetworkFlag(v, cmd.Flags())
	bindRunFlags(v, cmd.Flags())
	cmd.AddCommand(
		newPreflightCommand(v),
		newExternalIDCommand(v),
		newApplyPlanCommand(v),
		newStatusCommand(v),
		newWaitCommand(v),
		newDiscoverOrgCommand(v),
		newOnboardAccountsCommand(v),
		newSyncAccountsCommand(v),
		newServeWebhookCommand(v),
		newConfigureWebhookCommand(v),
	)
	return cmd
}

func newExternalIDCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "external-id",
		Short:         "Set or clear the External ID on an existing AWS setup",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDForCLI(cmd.Context(), v, password, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			setupID, _ := cmd.Flags().GetString("setup-id")
			value, _ := cmd.Flags().GetString("value")
			clearValue, _ := cmd.Flags().GetBool("clear")
			accountIDs, _ := cmd.Flags().GetStringSlice("account-id")
			externalIDFile, _ := cmd.Flags().GetString("external-id-file")
			apply, _ := cmd.Flags().GetBool("apply")
			yes, _ := cmd.Flags().GetBool("yes")
			if err := confirmApply(apply, yes, os.Stdin, os.Stderr); err != nil {
				return err
			}
			output, _ := cmd.Flags().GetString("output")
			summary, err := app.ChangeExternalID(cmd.Context(), app.ExternalIDConfig{
				Host:           v.GetString("host"),
				Username:       v.GetString("username"),
				Password:       password,
				NetworkID:      networkID,
				SetupID:        setupID,
				AccountIDs:     accountIDs,
				ExternalID:     value,
				Clear:          clearValue,
				ExternalIDFile: externalIDFile,
				Output:         output,
				APIPrefix:      v.GetString("api-prefix"),
				Insecure:       v.GetBool("insecure"),
				Timeout:        v.GetDuration("timeout"),
				Apply:          apply,
			})
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("setup-id", "", "existing Forward AWS setup ID")
	cmd.Flags().String("value", "", "customer-defined External ID to set")
	cmd.Flags().Bool("clear", false, "clear the External ID back to null")
	cmd.Flags().StringSlice("account-id", nil, "optional AWS account ID to change; repeatable or comma-separated")
	cmd.Flags().String("external-id-file", "", "CSV file of per-account External ID set/clear actions")
	cmd.Flags().String("output", "", "output JSON path for the generated PATCH payload")
	cmd.Flags().Bool("apply", false, "PATCH the generated setup payload into Forward")
	cmd.Flags().Bool("yes", false, "skip apply confirmation prompt")
	return cmd
}

func bindCommonFlags(v *viper.Viper, flags *pflag.FlagSet) {
	flags.String("host", "", "Forward base URL, for example https://fwd.app")
	flags.String("username", "", "Forward username")
	flags.String("password", "", "Forward password")
	flags.String("format", "json", "output format: json or human")
	flags.String("api-prefix", "/api", "API prefix")
	flags.Bool("insecure", false, "skip TLS certificate verification")
	flags.Duration("timeout", 60*time.Second, "HTTP timeout")
	mustBind(v, flags, "host")
	mustBind(v, flags, "username")
	mustBind(v, flags, "password")
	mustBind(v, flags, "format")
	mustBind(v, flags, "api-prefix")
	mustBind(v, flags, "insecure")
	mustBind(v, flags, "timeout")
}

func bindNetworkFlag(v *viper.Viper, flags *pflag.FlagSet) {
	flags.String("network-id", "", "Forward network ID")
	mustBind(v, flags, "network-id")
}

func bindRunFlags(v *viper.Viper, flags *pflag.FlagSet) {
	flags.String("snapshot-id", "", "optional snapshot ID to query instead of latest processed snapshot")
	bindProcessingFlags(v, flags)
	mustBind(v, flags, "snapshot-id")
}

func bindPreflightFlags(v *viper.Viper, flags *pflag.FlagSet) {
	flags.String("snapshot-id", "", "optional snapshot ID to query instead of latest processed snapshot")
	flags.String("query-id", "", "optional NQE query ID override; for multiple AWS setups it must select cloudAccount.cloudSetupId as Cloud Setup ID")
	flags.String("query-setup-param", "", "optional saved-query String parameter name to receive the single selected --setup-id")
	flags.StringSlice("setup-id", nil, "optional Forward AWS setup ID to sync; repeatable")
	flags.Bool("allow-no-org-evidence", false, "allow removals when no AWS Organizations evidence is visible in NQE")
	flags.Int("max-removals", 0, "maximum aggregate account removals allowed during apply; 0 disables the limit")
	flags.Float64("max-removal-percent", 0, "maximum removal percentage allowed per setup during apply; 0 disables the limit")
	flags.Duration("max-snapshot-age", 0, "fail if latest processed snapshot is older than this duration; 0 disables the check")
	flags.String("external-id-file", "", "CSV file of explicit per-account External IDs for mixed-ID setups")
	mustBind(v, flags, "snapshot-id")
	mustBind(v, flags, "query-id")
	mustBind(v, flags, "query-setup-param")
	mustBind(v, flags, "setup-id")
	mustBind(v, flags, "allow-no-org-evidence")
	mustBind(v, flags, "max-removals")
	mustBind(v, flags, "max-removal-percent")
	mustBind(v, flags, "max-snapshot-age")
	mustBind(v, flags, "external-id-file")
}

func bindProcessingFlags(v *viper.Viper, flags *pflag.FlagSet) {
	flags.String("query-id", "", "optional NQE query ID override; for multiple AWS setups it must select cloudAccount.cloudSetupId as Cloud Setup ID")
	flags.String("query-setup-param", "", "optional saved-query String parameter name to receive the single selected --setup-id")
	flags.StringSlice("setup-id", nil, "optional Forward AWS setup ID to sync; repeatable")
	flags.String("output", "", "output JSON path for generated PATCH payloads (defaults to aws_sync_payload_<timestamp>.json)")
	flags.String("manual-output", "", "optional JSON path for manual platform drag-and-drop payloads")
	flags.Bool("apply", false, "PATCH the generated setup payloads back into Forward")
	flags.Bool("yes", false, "skip apply confirmation prompt")
	flags.Bool("allow-removals", false, "allow planned account removals during apply")
	flags.Int("max-removals", 0, "maximum aggregate account removals allowed during apply; 0 disables the limit")
	flags.Float64("max-removal-percent", 0, "maximum removal percentage allowed per setup during apply; 0 disables the limit")
	flags.Bool("allow-no-candidates", false, "allow removals when no uncollected candidate accounts are visible")
	flags.Bool("allow-no-org-evidence", false, "allow removals when no AWS Organizations evidence is visible in NQE")
	flags.Duration("max-snapshot-age", 0, "fail if latest processed snapshot is older than this duration; 0 disables the check")
	flags.String("external-id-file", "", "CSV file of explicit per-account External IDs for mixed-ID setups")
	mustBind(v, flags, "query-id")
	mustBind(v, flags, "query-setup-param")
	mustBind(v, flags, "setup-id")
	mustBind(v, flags, "output")
	mustBind(v, flags, "manual-output")
	mustBind(v, flags, "apply")
	mustBind(v, flags, "yes")
	mustBind(v, flags, "allow-removals")
	mustBind(v, flags, "max-removals")
	mustBind(v, flags, "max-removal-percent")
	mustBind(v, flags, "allow-no-candidates")
	mustBind(v, flags, "allow-no-org-evidence")
	mustBind(v, flags, "max-snapshot-age")
	mustBind(v, flags, "external-id-file")
}

func newPreflightCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "preflight",
		Short:         "Check whether AWS sync is ready to plan and apply safely",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDForCLI(cmd.Context(), v, password, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			setupIDs, err := resolveSetupIDsForCLI(cmd.Context(), v, password, networkID, flagStringSlice(cmd, v, "setup-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			summary, err := app.Preflight(cmd.Context(), app.Config{
				Host:               v.GetString("host"),
				Username:           v.GetString("username"),
				Password:           password,
				NetworkID:          networkID,
				SnapshotID:         flagString(cmd, v, "snapshot-id"),
				QueryID:            flagString(cmd, v, "query-id"),
				QuerySetupParam:    flagString(cmd, v, "query-setup-param"),
				SetupIDs:           setupIDs,
				APIPrefix:          v.GetString("api-prefix"),
				Insecure:           v.GetBool("insecure"),
				Timeout:            v.GetDuration("timeout"),
				AllowNoOrgEvidence: flagBool(cmd, v, "allow-no-org-evidence"),
				MaxRemovals:        flagInt(cmd, v, "max-removals"),
				MaxRemovalPercent:  flagFloat64(cmd, v, "max-removal-percent"),
				MaxSnapshotAge:     flagDuration(cmd, v, "max-snapshot-age"),
				ExternalIDFile:     flagString(cmd, v, "external-id-file"),
			})
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	bindPreflightFlags(v, cmd.Flags())
	return cmd
}

func newStatusCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "status",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show snapshot status for a network or a specific snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newAPIClient(v)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDFromClientForCLI(cmd.Context(), client, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			result, err := monitor.Status(
				cmd.Context(),
				client,
				networkID,
				flagString(cmd, v, "snapshot-id"),
			)
			if err != nil {
				return err
			}
			return emitJSON(result)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("snapshot-id", "", "optional snapshot ID to filter status output")
	mustBind(v, cmd.Flags(), "snapshot-id")
	return cmd
}

func newApplyPlanCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "apply-plan",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Apply a previously reviewed payload file without recomputing the plan",
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			if !v.GetBool("yes") {
				return fmt.Errorf("apply-plan requires --yes")
			}
			networkID, err := resolveNetworkIDForCLI(cmd.Context(), v, password, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			summary, err := app.ApplyPlan(cmd.Context(), app.ApplyPlanConfig{
				Host:              v.GetString("host"),
				Username:          v.GetString("username"),
				Password:          password,
				NetworkID:         networkID,
				PlanPath:          flagString(cmd, v, "plan"),
				APIPrefix:         v.GetString("api-prefix"),
				Insecure:          v.GetBool("insecure"),
				Timeout:           v.GetDuration("timeout"),
				AllowRemovals:     flagBool(cmd, v, "allow-removals"),
				MaxRemovals:       flagInt(cmd, v, "max-removals"),
				MaxRemovalPercent: flagFloat64(cmd, v, "max-removal-percent"),
			})
			if err != nil {
				return err
			}
			return emitJSON(summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("plan", "aws_sync_payload.json", "reviewed payload file to apply")
	cmd.Flags().Bool("yes", false, "confirm applying the reviewed payload file")
	cmd.Flags().Bool("allow-removals", false, "allow reviewed commercial-partition account removals; GovCloud removals must use their source workflow")
	cmd.Flags().Int("max-removals", 0, "maximum aggregate account removals allowed; 0 disables the limit")
	cmd.Flags().Float64("max-removal-percent", 0, "maximum removal percentage allowed per setup; 0 disables the limit")
	mustBind(v, cmd.Flags(), "plan")
	mustBind(v, cmd.Flags(), "yes")
	mustBind(v, cmd.Flags(), "allow-removals")
	mustBind(v, cmd.Flags(), "max-removals")
	mustBind(v, cmd.Flags(), "max-removal-percent")
	return cmd
}

func newWaitCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "wait",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Wait for a snapshot to reach a desired state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newAPIClient(v)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDFromClientForCLI(cmd.Context(), client, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), v.GetDuration("timeout"))
			defer cancel()
			result, err := monitor.Wait(
				ctx,
				client,
				networkID,
				flagString(cmd, v, "snapshot-id"),
				flagString(cmd, v, "wait-for-state"),
				flagDuration(cmd, v, "poll-interval"),
			)
			if err != nil {
				return err
			}
			return emitJSON(result)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("snapshot-id", "", "snapshot ID to monitor")
	cmd.Flags().String("wait-for-state", "PROCESSED", "desired snapshot state")
	cmd.Flags().Duration("poll-interval", 10*time.Second, "poll interval while waiting")
	mustBind(v, cmd.Flags(), "snapshot-id")
	mustBind(v, cmd.Flags(), "wait-for-state")
	mustBind(v, cmd.Flags(), "poll-interval")
	_ = cmd.MarkFlagRequired("snapshot-id")
	return cmd
}

func newDiscoverOrgCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "discover-org",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Discover AWS Organizations accounts and write Forward onboarding payloads",
		RunE: func(cmd *cobra.Command, _ []string) error {
			setupIDs := cleanSetupIDs(flagStringSlice(cmd, v, "setup-id"))
			if len(setupIDs) != 1 {
				return fmt.Errorf("discover-org requires exactly one --setup-id for the new Forward AWS setup")
			}
			password := ""
			networkID := flagString(cmd, v, "network-id")
			if strings.TrimSpace(v.GetString("host")) != "" {
				var err error
				password, err = resolvePassword(v, os.Stdin, os.Stderr)
				if err != nil {
					return err
				}
				networkID, err = resolveNetworkIDForCLI(cmd.Context(), v, password, networkID, os.Stdin, os.Stderr)
				if err != nil {
					return err
				}
			}

			credentialMode := flagString(cmd, v, "credential-mode")
			collectorSecret, err := resolveCollectorSecret(v, credentialMode, flagBool(cmd, v, "post"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			if err := confirmPost(flagBool(cmd, v, "post"), flagBool(cmd, v, "yes"), setupIDs[0], os.Stdin, os.Stderr); err != nil {
				return err
			}
			discovered, err := awsorg.Discover(cmd.Context(), awsorg.Config{
				Profile:          flagString(cmd, v, "aws-profile"),
				Region:           flagString(cmd, v, "aws-region"),
				IncludeSuspended: flagBool(cmd, v, "include-suspended"),
			})
			if err != nil {
				return err
			}
			source := app.AWSOrganizationSource{
				OrganizationID:      discovered.OrganizationID,
				ManagementAccountID: discovered.ManagementAccountID,
				SkippedAccountCount: discovered.SkippedAccountCount,
				Partition:           discovered.Partition,
			}
			source.Accounts = make([]app.AWSOrganizationAccount, 0, len(discovered.Accounts))
			for _, account := range discovered.Accounts {
				source.Accounts = append(source.Accounts, app.AWSOrganizationAccount{
					ID:        account.ID,
					Name:      account.Name,
					Email:     account.Email,
					State:     account.State,
					Status:    account.Status,
					ParentIDs: account.ParentIDs,
				})
			}
			summary, err := app.RunAWSOrganizations(cmd.Context(), app.AWSOrganizationConfig{
				Host:                     v.GetString("host"),
				Username:                 v.GetString("username"),
				Password:                 password,
				NetworkID:                networkID,
				SetupIDs:                 setupIDs,
				Output:                   flagString(cmd, v, "output"),
				ManualOutput:             flagString(cmd, v, "manual-output"),
				RoleName:                 flagString(cmd, v, "role-name"),
				ExternalID:               flagString(cmd, v, "external-id"),
				Regions:                  flagStringSlice(cmd, v, "collect-region"),
				CredentialMode:           credentialMode,
				CollectorAccessKeyID:     flagString(cmd, v, "collector-access-key-id"),
				CollectorSecretAccessKey: collectorSecret,
				Post:                     flagBool(cmd, v, "post"),
				APIPrefix:                v.GetString("api-prefix"),
				Insecure:                 v.GetBool("insecure"),
				Timeout:                  v.GetDuration("timeout"),
				IncludeManual:            true,
			}, source)
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().StringSlice("setup-id", nil, "new Forward AWS setup ID/name for generated onboarding payloads")
	cmd.Flags().String("role-name", "", "AWS IAM role name that Forward will assume in each discovered account")
	cmd.Flags().String("external-id", "", "optional external ID; fetched from Forward when host credentials are supplied")
	cmd.Flags().StringSlice("collect-region", nil, "AWS region for Forward to collect; repeatable or comma-separated")
	cmd.Flags().String("credential-mode", app.CredentialModeForwardRole, "Forward collection credential mode: forward-role, static-keys, or instance-profile")
	cmd.Flags().String("collector-access-key-id", "", "collector AWS access key ID for static-keys mode")
	cmd.Flags().String("collector-secret-access-key", "", "collector AWS secret access key for static-keys mode; prefer AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY")
	cmd.Flags().Bool("post", false, "POST the create payload to Forward after writing JSON files")
	cmd.Flags().Bool("yes", false, "skip create confirmation prompt")
	cmd.Flags().String("output", "", "Forward create-setup POST JSON path (defaults to aws_create_payload_<timestamp>.json)")
	cmd.Flags().String("manual-output", "", "manual drag-and-drop JSON path (defaults to fwd_accounts_data_<timestamp>.json)")
	cmd.Flags().String("aws-profile", "", "AWS shared config profile; empty uses the default AWS credential chain")
	cmd.Flags().String("aws-region", "us-east-1", "AWS region for Organizations API client")
	cmd.Flags().Bool("include-suspended", false, "include suspended AWS organization accounts")
	mustBind(v, cmd.Flags(), "setup-id")
	mustBind(v, cmd.Flags(), "role-name")
	mustBind(v, cmd.Flags(), "external-id")
	mustBind(v, cmd.Flags(), "collect-region")
	mustBind(v, cmd.Flags(), "credential-mode")
	mustBind(v, cmd.Flags(), "collector-access-key-id")
	mustBind(v, cmd.Flags(), "collector-secret-access-key")
	mustBind(v, cmd.Flags(), "post")
	mustBind(v, cmd.Flags(), "yes")
	mustBind(v, cmd.Flags(), "output")
	mustBind(v, cmd.Flags(), "manual-output")
	mustBind(v, cmd.Flags(), "aws-profile")
	mustBind(v, cmd.Flags(), "aws-region")
	mustBind(v, cmd.Flags(), "include-suspended")
	return cmd
}

func newOnboardAccountsCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "onboard-accounts",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Write Forward onboarding payloads from a reviewed AWS account manifest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			setupIDs := cleanSetupIDs(flagStringSlice(cmd, v, "setup-id"))
			if len(setupIDs) != 1 {
				return fmt.Errorf("onboard-accounts requires exactly one --setup-id for the new Forward AWS setup")
			}
			accounts, err := app.LoadAWSAccountManifest(flagString(cmd, v, "accounts-file"))
			if err != nil {
				return err
			}
			password := ""
			networkID := flagString(cmd, v, "network-id")
			if strings.TrimSpace(v.GetString("host")) != "" {
				password, err = resolvePassword(v, os.Stdin, os.Stderr)
				if err != nil {
					return err
				}
				networkID, err = resolveNetworkIDForCLI(cmd.Context(), v, password, networkID, os.Stdin, os.Stderr)
				if err != nil {
					return err
				}
			}

			credentialMode := flagString(cmd, v, "credential-mode")
			collectorSecret, err := resolveCollectorSecret(v, credentialMode, flagBool(cmd, v, "post"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			if err := confirmPost(flagBool(cmd, v, "post"), flagBool(cmd, v, "yes"), setupIDs[0], os.Stdin, os.Stderr); err != nil {
				return err
			}
			summary, err := app.RunAWSAccountManifest(cmd.Context(), app.AWSOrganizationConfig{
				Host:                     v.GetString("host"),
				Username:                 v.GetString("username"),
				Password:                 password,
				NetworkID:                networkID,
				SetupIDs:                 setupIDs,
				Output:                   flagString(cmd, v, "output"),
				ManualOutput:             flagString(cmd, v, "manual-output"),
				RoleName:                 flagString(cmd, v, "role-name"),
				ExternalID:               flagString(cmd, v, "external-id"),
				Regions:                  flagStringSlice(cmd, v, "collect-region"),
				CredentialMode:           credentialMode,
				CollectorAccessKeyID:     flagString(cmd, v, "collector-access-key-id"),
				CollectorSecretAccessKey: collectorSecret,
				Post:                     flagBool(cmd, v, "post"),
				APIPrefix:                v.GetString("api-prefix"),
				Insecure:                 v.GetBool("insecure"),
				Timeout:                  v.GetDuration("timeout"),
				IncludeManual:            true,
				Partition:                flagString(cmd, v, "partition"),
			}, accounts)
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("accounts-file", "", "reviewed JSON array of AWS accounts with id and optional name")
	cmd.Flags().StringSlice("setup-id", nil, "new Forward AWS setup ID/name for generated onboarding payloads")
	cmd.Flags().String("role-name", "", "AWS IAM role name that Forward will assume in each account")
	cmd.Flags().String("external-id", "", "optional external ID; fetched from Forward when host credentials are supplied")
	cmd.Flags().StringSlice("collect-region", nil, "AWS region for Forward to collect; repeatable or comma-separated")
	cmd.Flags().String("partition", "aws", "AWS ARN partition: aws, aws-us-gov, or aws-cn")
	cmd.Flags().String("credential-mode", app.CredentialModeForwardRole, "Forward collection credential mode: forward-role, static-keys, or instance-profile")
	cmd.Flags().String("collector-access-key-id", "", "collector AWS access key ID for static-keys mode")
	cmd.Flags().String("collector-secret-access-key", "", "collector AWS secret access key for static-keys mode; prefer AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY")
	cmd.Flags().Bool("post", false, "POST the create payload to Forward after writing JSON files")
	cmd.Flags().Bool("yes", false, "skip create confirmation prompt")
	cmd.Flags().String("output", "", "Forward create-setup POST JSON path (defaults to aws_create_payload_<timestamp>.json)")
	cmd.Flags().String("manual-output", "", "manual drag-and-drop JSON path (defaults to fwd_accounts_data_<timestamp>.json)")
	for _, name := range []string{"accounts-file", "setup-id", "role-name", "external-id", "collect-region", "partition", "credential-mode", "collector-access-key-id", "collector-secret-access-key", "post", "yes", "output", "manual-output"} {
		mustBind(v, cmd.Flags(), name)
	}
	return cmd
}

func newSyncAccountsCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "sync-accounts",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Plan or apply an existing AWS setup from an authoritative account manifest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			setupIDs := cleanSetupIDs(flagStringSlice(cmd, v, "setup-id"))
			if len(setupIDs) != 1 {
				return fmt.Errorf("sync-accounts requires exactly one --setup-id")
			}
			accounts, err := app.LoadAWSAccountManifest(flagString(cmd, v, "accounts-file"))
			if err != nil {
				return err
			}
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			networkID, err := resolveNetworkIDForCLI(cmd.Context(), v, password, flagString(cmd, v, "network-id"), os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			apply := flagBool(cmd, v, "apply")
			if err := confirmApply(apply, flagBool(cmd, v, "yes"), os.Stdin, os.Stderr); err != nil {
				return err
			}
			summary, err := app.SyncAWSAccountManifest(cmd.Context(), app.Config{
				Host:              v.GetString("host"),
				Username:          v.GetString("username"),
				Password:          password,
				NetworkID:         networkID,
				SetupIDs:          setupIDs,
				Output:            flagString(cmd, v, "output"),
				ManualOutput:      flagString(cmd, v, "manual-output"),
				APIPrefix:         v.GetString("api-prefix"),
				Insecure:          v.GetBool("insecure"),
				Timeout:           v.GetDuration("timeout"),
				Apply:             apply,
				AllowRemovals:     flagBool(cmd, v, "allow-removals"),
				MaxRemovals:       flagInt(cmd, v, "max-removals"),
				MaxRemovalPercent: flagFloat64(cmd, v, "max-removal-percent"),
				ExternalIDFile:    flagString(cmd, v, "external-id-file"),
			}, accounts)
			if err != nil {
				return err
			}
			return emitResult(cmd, v, summary)
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().String("accounts-file", "", "authoritative reviewed JSON array of AWS accounts with id and optional name")
	cmd.Flags().StringSlice("setup-id", nil, "existing Forward AWS setup ID")
	cmd.Flags().String("output", "", "output JSON path for the generated PATCH payload")
	cmd.Flags().String("manual-output", "", "optional UI-friendly account JSON output path")
	cmd.Flags().Bool("apply", false, "PATCH the generated setup payload into Forward")
	cmd.Flags().Bool("yes", false, "skip apply confirmation prompt")
	cmd.Flags().Bool("allow-removals", false, "allow reviewed manifest entries to remove accounts from the setup")
	cmd.Flags().Int("max-removals", 0, "maximum aggregate account removals allowed; 0 disables the limit")
	cmd.Flags().Float64("max-removal-percent", 0, "maximum removal percentage allowed for the setup; 0 disables the limit")
	cmd.Flags().String("external-id-file", "", "CSV file of explicit per-account External IDs")
	for _, name := range []string{"accounts-file", "setup-id", "output", "manual-output", "apply", "yes", "allow-removals", "max-removals", "max-removal-percent", "external-id-file"} {
		mustBind(v, cmd.Flags(), name)
	}
	return cmd
}

func newServeWebhookCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "serve-webhook",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Receive Forward SNAPSHOT_READY webhooks and run awssync for the exact snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := resolvePassword(v, os.Stdin, os.Stderr)
			if err != nil {
				return err
			}
			if flagBool(cmd, v, "apply") && !flagBool(cmd, v, "yes") {
				return fmt.Errorf("serve-webhook with --apply requires --yes")
			}
			srv, err := webhook.New(webhook.Config{
				Listen:        flagString(cmd, v, "listen"),
				Path:          flagString(cmd, v, "path"),
				BasicUsername: flagString(cmd, v, "webhook-basic-username"),
				BasicPassword: flagString(cmd, v, "webhook-basic-password"),
				App: app.Config{
					Host:               v.GetString("host"),
					Username:           v.GetString("username"),
					Password:           password,
					QueryID:            flagString(cmd, v, "query-id"),
					QuerySetupParam:    flagString(cmd, v, "query-setup-param"),
					SetupIDs:           flagStringSlice(cmd, v, "setup-id"),
					Output:             flagString(cmd, v, "output"),
					ManualOutput:       flagString(cmd, v, "manual-output"),
					APIPrefix:          v.GetString("api-prefix"),
					Insecure:           v.GetBool("insecure"),
					Timeout:            v.GetDuration("timeout"),
					Apply:              flagBool(cmd, v, "apply"),
					AllowRemovals:      flagBool(cmd, v, "allow-removals"),
					MaxRemovals:        flagInt(cmd, v, "max-removals"),
					MaxRemovalPercent:  flagFloat64(cmd, v, "max-removal-percent"),
					AllowNoCandidates:  flagBool(cmd, v, "allow-no-candidates"),
					AllowNoOrgEvidence: flagBool(cmd, v, "allow-no-org-evidence"),
					MaxSnapshotAge:     flagDuration(cmd, v, "max-snapshot-age"),
					ExternalIDFile:     flagString(cmd, v, "external-id-file"),
				},
			})
			if err != nil {
				return err
			}
			return srv.Run(cmd.Context())
		},
	}
	cmd.Flags().String("listen", ":8080", "listen address for the webhook receiver")
	cmd.Flags().String("path", "/forward/snapshot-ready", "HTTP path for webhook POST requests")
	cmd.Flags().String("webhook-basic-username", "", "optional Basic Auth username required on incoming webhook requests")
	cmd.Flags().String("webhook-basic-password", "", "optional Basic Auth password required on incoming webhook requests")
	bindProcessingFlags(v, cmd.Flags())
	mustBind(v, cmd.Flags(), "listen")
	mustBind(v, cmd.Flags(), "path")
	mustBind(v, cmd.Flags(), "webhook-basic-username")
	mustBind(v, cmd.Flags(), "webhook-basic-password")
	return cmd
}

func newConfigureWebhookCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "configure-webhook",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create or update Forward SNAPSHOT_READY webhooks for awssync",
		RunE: func(cmd *cobra.Command, _ []string) error {
			webhookURL := strings.TrimSpace(flagString(cmd, v, "webhook-url"))
			if webhookURL == "" {
				return fmt.Errorf("--webhook-url is required")
			}
			networkID := strings.TrimSpace(flagString(cmd, v, "network-id"))
			dryRun := flagBool(cmd, v, "dry-run")
			var client *api.Client
			if networkID == "" || !dryRun || flagBool(cmd, v, "test-webhook") {
				var err error
				client, err = newAPIClient(v)
				if err != nil {
					return err
				}
				networkID, err = resolveNetworkIDFromClientForCLI(cmd.Context(), client, networkID, os.Stdin, os.Stderr)
				if err != nil {
					return err
				}
			}
			if strings.TrimSpace(networkID) == "" {
				return fmt.Errorf("--network-id is required for --dry-run without Forward credentials")
			}
			name := strings.TrimSpace(flagString(cmd, v, "webhook-name"))
			if name == "" {
				name = "awssync-snapshot-ready"
			}
			webhookUser := strings.TrimSpace(flagString(cmd, v, "webhook-basic-username"))
			webhookPass := flagString(cmd, v, "webhook-basic-password")
			var credential *api.WebhookBasicAuth
			if webhookUser != "" || strings.TrimSpace(webhookPass) != "" {
				if webhookUser == "" || strings.TrimSpace(webhookPass) == "" {
					return fmt.Errorf("both --webhook-basic-username and --webhook-basic-password are required")
				}
				credential = &api.WebhookBasicAuth{
					Type:     "BASIC_AUTH",
					Username: webhookUser,
					Password: webhookPass,
				}
			}

			setupIDs := cleanSetupIDs(flagStringSlice(cmd, v, "setup-id"))
			perSetup := flagBool(cmd, v, "webhook-per-setup")
			if perSetup && len(setupIDs) == 0 {
				return fmt.Errorf("--webhook-per-setup requires at least one --setup-id")
			}
			scopes := [][]string{setupIDs}
			if perSetup {
				scopes = scopes[:0]
				for _, setupID := range setupIDs {
					scopes = append(scopes, []string{setupID})
				}
			}

			results := make([]map[string]any, 0, len(scopes))
			for _, scopeSetupIDs := range scopes {
				webhookName := name
				if perSetup {
					webhookName = name + "-" + webhookNameSuffix(scopeSetupIDs[0])
				}
				webhookPayload, err := buildWebhookPayload(
					webhookName,
					strings.TrimSpace(flagString(cmd, v, "webhook-description")),
					webhookURL,
					networkID,
					scopeSetupIDs,
					flagBool(cmd, v, "disable-webhook-ssl-validation"),
					credential,
				)
				if err != nil {
					return err
				}
				if flagBool(cmd, v, "test-webhook") {
					result, err := client.TestNewWebhook(cmd.Context(), webhookPayload)
					if err != nil {
						return err
					}
					if strings.TrimSpace(result.Error) != "" {
						return fmt.Errorf("webhook test failed for %s: %s", webhookPayload.Name, result.Error)
					}
				}
				action := "created"
				if dryRun {
					action = "dry_run"
				} else {
					if err := client.AddWebhook(cmd.Context(), webhookPayload); err != nil {
						if !api.IsDuplicateWebhookError(err) {
							return err
						}
						if err := client.UpdateWebhook(cmd.Context(), webhookPayload.Name, webhookPayload); err != nil {
							return err
						}
						action = "updated"
					}
				}
				payloadForOutput := webhookPayload
				if payloadForOutput.Credential != nil {
					payloadForOutput.Credential = &api.WebhookBasicAuth{
						Type:     payloadForOutput.Credential.Type,
						Username: payloadForOutput.Credential.Username,
						Password: "<redacted>",
					}
				}
				results = append(results, map[string]any{
					"action":    action,
					"name":      webhookPayload.Name,
					"url":       webhookPayload.URL,
					"setup_ids": scopeSetupIDs,
					"payload":   payloadForOutput,
				})
			}
			return emitJSON(map[string]any{
				"network_id": networkID,
				"setup_ids":  setupIDs,
				"webhooks":   results,
			})
		},
	}
	bindNetworkFlag(v, cmd.Flags())
	cmd.Flags().StringSlice("setup-id", nil, "optional Forward AWS setup ID for receiver scoping; repeatable")
	cmd.Flags().String("webhook-url", "", "public or Forward-reachable receiver URL")
	cmd.Flags().String("webhook-name", "awssync-snapshot-ready", "Forward webhook name")
	cmd.Flags().String("webhook-description", "Run awssync when a snapshot is ready", "Forward webhook description")
	cmd.Flags().String("webhook-basic-username", "", "Basic Auth username Forward sends to the receiver")
	cmd.Flags().String("webhook-basic-password", "", "Basic Auth password Forward sends to the receiver")
	cmd.Flags().Bool("disable-webhook-ssl-validation", false, "disable webhook receiver TLS validation in Forward")
	cmd.Flags().Bool("test-webhook", false, "test the webhook URL before creating it")
	cmd.Flags().Bool("webhook-per-setup", false, "create or update one webhook per --setup-id")
	cmd.Flags().Bool("dry-run", false, "print webhook payloads without creating or updating Forward webhooks")
	mustBind(v, cmd.Flags(), "setup-id")
	mustBind(v, cmd.Flags(), "webhook-url")
	mustBind(v, cmd.Flags(), "webhook-name")
	mustBind(v, cmd.Flags(), "webhook-description")
	mustBind(v, cmd.Flags(), "webhook-basic-username")
	mustBind(v, cmd.Flags(), "webhook-basic-password")
	mustBind(v, cmd.Flags(), "disable-webhook-ssl-validation")
	mustBind(v, cmd.Flags(), "test-webhook")
	mustBind(v, cmd.Flags(), "webhook-per-setup")
	mustBind(v, cmd.Flags(), "dry-run")
	return cmd
}

func buildWebhookPayload(
	name string,
	description string,
	webhookURL string,
	networkID string,
	setupIDs []string,
	disableSSLValidation bool,
	credential *api.WebhookBasicAuth,
) (api.Webhook, error) {
	scopedURL, err := appendSetupIDsToURL(webhookURL, setupIDs)
	if err != nil {
		return api.Webhook{}, err
	}
	if len(setupIDs) > 0 {
		description = strings.TrimSpace(description + " for setup(s) " + strings.Join(setupIDs, ", "))
	}
	webhookPayload := api.Webhook{
		Name:                 name,
		Description:          description,
		URL:                  scopedURL,
		DisableSSLValidation: disableSSLValidation,
		EventParams: api.WebhookEventParams{
			Type:       "SNAPSHOT_READY",
			NetworkIDs: []string{networkID},
		},
		Credential: credential,
		Enabled:    true,
		Template: api.WebhookTemplate{
			PayloadFormat: "JSON",
			Template:      snapshotReadyWebhookTemplate(),
		},
	}
	return webhookPayload, nil
}

func appendSetupIDsToURL(rawURL string, setupIDs []string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("parse --webhook-url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("--webhook-url must be absolute")
	}
	values := parsed.Query()
	for _, setupID := range cleanSetupIDs(setupIDs) {
		values.Add("setupId", setupID)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func webhookNameSuffix(setupID string) string {
	var b strings.Builder
	for _, r := range setupID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	value := strings.Trim(b.String(), "-_")
	if value == "" {
		return "setup"
	}
	return value
}

func snapshotReadyWebhookTemplate() string {
	return `{
"id": "$id",
"type": "$type",
"networkId": "$networkId",
"snapshotId": "$snapshotId"
}`
}

func newAPIClient(v *viper.Viper) (*api.Client, error) {
	password, err := resolvePassword(v, os.Stdin, os.Stderr)
	if err != nil {
		return nil, err
	}
	return api.NewClient(
		v.GetString("host"),
		v.GetString("api-prefix"),
		v.GetString("username"),
		password,
		v.GetBool("insecure"),
		v.GetDuration("timeout"),
	)
}

func mustBind(v *viper.Viper, flags *pflag.FlagSet, name string) {
	if err := v.BindPFlag(name, flags.Lookup(name)); err != nil {
		panic(err)
	}
	aliases := []string{"AWSSYNC_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))}
	switch name {
	case "host", "network-id", "query-id", "query-setup-param", "setup-id":
		aliases = append(aliases, "FWD_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
	case "username":
		aliases = append(aliases, "FWD_USERNAME", "FWD_USER")
	case "password":
		aliases = append(aliases, "FWD_PASSWORD", "FWD_PASS")
	}
	binding := append([]string{name}, aliases...)
	if err := v.BindEnv(binding...); err != nil {
		panic(err)
	}
}

func flagString(cmd *cobra.Command, v *viper.Viper, name string) string {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetString(name)
		return value
	}
	return v.GetString(name)
}

func flagStringSlice(cmd *cobra.Command, v *viper.Viper, name string) []string {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetStringSlice(name)
		return value
	}
	return v.GetStringSlice(name)
}

func cleanSetupIDs(setupIDs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(setupIDs))
	for _, setupID := range setupIDs {
		setupID = strings.TrimSpace(setupID)
		if setupID == "" || seen[setupID] {
			continue
		}
		seen[setupID] = true
		result = append(result, setupID)
	}
	return result
}

func flagBool(cmd *cobra.Command, v *viper.Viper, name string) bool {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetBool(name)
		return value
	}
	return v.GetBool(name)
}

func flagInt(cmd *cobra.Command, v *viper.Viper, name string) int {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetInt(name)
		return value
	}
	return v.GetInt(name)
}

func flagFloat64(cmd *cobra.Command, v *viper.Viper, name string) float64 {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetFloat64(name)
		return value
	}
	return v.GetFloat64(name)
}

func flagDuration(cmd *cobra.Command, v *viper.Viper, name string) time.Duration {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		value, _ := cmd.Flags().GetDuration(name)
		return value
	}
	return v.GetDuration(name)
}

func resolvePassword(v *viper.Viper, stdin *os.File, stderr io.Writer) (string, error) {
	password := v.GetString("password")
	if strings.TrimSpace(password) != "" {
		return password, nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return "", fmt.Errorf("password is required; use --password, FWD_PASS, or AWSSYNC_PASSWORD")
	}
	fmt.Fprint(stderr, "Forward password: ")
	data, err := term.ReadPassword(int(stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	password = string(data)
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password is required")
	}
	return password, nil
}

func resolveCollectorSecret(v *viper.Viper, credentialMode string, post bool, stdin *os.File, stderr io.Writer) (string, error) {
	if strings.TrimSpace(strings.ToLower(credentialMode)) != app.CredentialModeStaticKeys {
		return "", nil
	}
	secret := v.GetString("collector-secret-access-key")
	if strings.TrimSpace(secret) != "" {
		return secret, nil
	}
	if !post {
		return "", nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return "", fmt.Errorf("collector secret access key is required for --post with --credential-mode static-keys; use AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY")
	}
	fmt.Fprint(stderr, "Collector AWS secret access key for Forward: ")
	data, err := term.ReadPassword(int(stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read collector secret access key: %w", err)
	}
	secret = string(data)
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("collector secret access key is required")
	}
	return secret, nil
}

func resolveOutputFormat(cmd *cobra.Command, v *viper.Viper) (string, error) {
	value := strings.TrimSpace(strings.ToLower(flagString(cmd, v, "format")))
	if value == "" {
		value = "json"
	}
	switch value {
	case "json", "human":
		return value, nil
	default:
		return "json", fmt.Errorf("invalid --format %q; expected \"json\" or \"human\"", value)
	}
}

func emitResult(cmd *cobra.Command, v *viper.Viper, value any) error {
	format, err := resolveOutputFormat(cmd, v)
	if err != nil {
		return err
	}
	if format != "human" {
		return emitJSON(value)
	}
	switch summary := value.(type) {
	case *app.PreflightSummary:
		return emitPreflightHuman(summary)
	case *app.Summary:
		return emitSummaryHuman(summary)
	case *app.ExternalIDSummary:
		return emitExternalIDHuman(summary)
	default:
		return emitJSON(value)
	}
}

func emitExternalIDHuman(summary *app.ExternalIDSummary) error {
	fmt.Fprintln(os.Stdout, "External ID migration report")
	fmt.Fprintf(os.Stdout, "  host:       %s\n", summary.Host)
	fmt.Fprintf(os.Stdout, "  network:    %s\n", summary.NetworkID)
	fmt.Fprintf(os.Stdout, "  setup:      %s\n", summary.SetupID)
	fmt.Fprintf(os.Stdout, "  mode:       %s\n", summary.Mode)
	fmt.Fprintf(os.Stdout, "  accounts:   %d total, %d selected, %d changed, %d unchanged\n", summary.AccountCount, summary.SelectedAccountCount, summary.ChangedAccountCount, summary.UnchangedAccountCount)
	fmt.Fprintf(os.Stdout, "  actions:    %d set, %d clear\n", summary.SetAccountCount, summary.ClearedAccountCount)
	fmt.Fprintf(os.Stdout, "  prior ID:   configured=%t consistent=%t\n", summary.PreviousExternalIDConfigured, summary.PreviousExternalIDConsistent)
	fmt.Fprintf(os.Stdout, "  target ID:  configured=%t consistent=%t\n", summary.TargetExternalIDConfigured, summary.TargetExternalIDConsistent)
	fmt.Fprintf(os.Stdout, "  apply:      %t\n", summary.Apply)
	fmt.Fprintf(os.Stdout, "  patched:    %t\n", summary.Patched)
	fmt.Fprintf(os.Stdout, "  output:     %s\n", summary.Output)
	fmt.Fprintf(os.Stdout, "  sha256:     %s\n", summary.PayloadSHA256)
	return nil
}

func emitPreflightHuman(summary *app.PreflightSummary) error {
	fmt.Fprintf(os.Stdout, "Preflight report\n")
	fmt.Fprintf(os.Stdout, "  host:     %s\n", summary.Host)
	fmt.Fprintf(os.Stdout, "  network:  %s\n", summary.NetworkID)
	fmt.Fprintf(os.Stdout, "  ready:    %t\n", summary.Ready)
	fmt.Fprintf(os.Stdout, "  accounts: %d rows\n", summary.FetchedItemCount)
	if len(summary.SelectedSetupIDs) > 0 {
		fmt.Fprintf(os.Stdout, "  setups:   %s\n", strings.Join(summary.SelectedSetupIDs, ", "))
	}
	fmt.Fprintln(os.Stdout, "\nChecks:")
	for _, check := range summary.Checks {
		fmt.Fprintf(os.Stdout, "  - %-25s %-4s %s\n", check.Name, strings.ToUpper(check.Status), check.Message)
	}
	fmt.Fprintln(os.Stdout, "\nSetups:")
	for _, setup := range summary.PlannedSetups {
		fmt.Fprintf(
			os.Stdout,
			"  - %s: configured=%d, discovered=%d, candidates=%d, added=%d, removed=%d\n",
			setup.SetupID,
			setup.ConfiguredAccountCount,
			setup.NQEAccountRowCount,
			setup.NQECandidateRowCount,
			len(setup.AddedAccounts),
			len(setup.RemovedAccounts),
		)
		if len(setup.AddedAccounts) > 0 {
			fmt.Fprintf(os.Stdout, "    added:   %s\n", accountSummaryIDs(setup.AddedAccounts))
		}
		if len(setup.RemovedAccounts) > 0 {
			fmt.Fprintf(os.Stdout, "    removed: %s\n", accountSummaryIDs(setup.RemovedAccounts))
		}
		fmt.Fprintf(os.Stdout, "    %s\n", setup.OrganizationDiscoveryMessage)
	}
	if summary.Ready {
		fmt.Fprintln(os.Stdout, "\nNext command:")
		fmt.Fprintf(os.Stdout, "  awssync --network-id %s --apply --yes\n", summary.NetworkID)
	} else {
		fmt.Fprintln(os.Stdout, "\nPreflight is not ready; fix failed checks and rerun preflight.")
	}
	return nil
}

func emitSummaryHuman(summary *app.Summary) error {
	if summary.Source == "aws_organizations" || (summary.Source == "account_manifest" && summary.CreatePayload != nil) {
		return emitAWSOrganizationsHuman(summary)
	}
	fmt.Fprintf(os.Stdout, "Sync report\n")
	fmt.Fprintf(os.Stdout, "  host:      %s\n", summary.Host)
	fmt.Fprintf(os.Stdout, "  network:   %s\n", summary.NetworkID)
	if summary.Source != "" {
		fmt.Fprintf(os.Stdout, "  source:    %s\n", summary.Source)
	}
	if summary.AWSOrganizationID != "" {
		fmt.Fprintf(os.Stdout, "  aws org:   %s\n", summary.AWSOrganizationID)
	}
	fmt.Fprintf(os.Stdout, "  apply:     %t\n", summary.Apply)
	if len(summary.SelectedSetupIDs) > 0 {
		fmt.Fprintf(os.Stdout, "  setups:    %s\n", strings.Join(summary.SelectedSetupIDs, ", "))
	}
	fmt.Fprintf(os.Stdout, "  output:    %s\n", summary.Output)
	if summary.ManualOutput != "" {
		fmt.Fprintf(os.Stdout, "  manual:    %s\n", summary.ManualOutput)
	}
	fmt.Fprintf(os.Stdout, "  fetched:   %d\n", summary.FetchedItemCount)
	fmt.Fprintf(os.Stdout, "  planned:   %d\n", summary.PlannedSetupCount)
	fmt.Fprintf(os.Stdout, "  patched:   %d\n", summary.PatchedSetupCount)
	if summary.RemovalBlocked {
		fmt.Fprintln(os.Stdout, "\nApply blocked. Add --allow-removals, --allow-no-candidates, and --allow-no-org-evidence as needed.")
	}
	fmt.Fprintln(os.Stdout, "\nSetups:")
	addedTotal, removedTotal := 0, 0
	for _, setup := range summary.PlannedSetups {
		addedTotal += len(setup.AddedAccounts)
		removedTotal += len(setup.RemovedAccounts)
		fmt.Fprintf(
			os.Stdout,
			"  - %s: add=%d remove=%d unchanged=%d\n",
			setup.SetupID,
			len(setup.AddedAccounts),
			len(setup.RemovedAccounts),
			setup.UnchangedAccountCount,
		)
		if len(setup.AddedAccounts) > 0 {
			fmt.Fprintf(os.Stdout, "    added:   %s\n", accountSummaryIDs(setup.AddedAccounts))
		}
		if len(setup.RemovedAccounts) > 0 {
			fmt.Fprintf(os.Stdout, "    removed: %s\n", accountSummaryIDs(setup.RemovedAccounts))
		}
		fmt.Fprintf(os.Stdout, "    %s\n", setup.OrganizationDiscoveryMessage)
	}
	fmt.Fprintln(os.Stdout, "\nSummary:")
	fmt.Fprintf(os.Stdout, "  total added=%d, total removed=%d\n", addedTotal, removedTotal)
	return nil
}

func accountSummaryIDs(accounts []app.AccountSummary) string {
	ids := make([]string, 0, len(accounts))
	for _, account := range accounts {
		ids = append(ids, account.AccountID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func emitAWSOrganizationsHuman(summary *app.Summary) error {
	title := "AWS Organizations onboarding report"
	if summary.Source == "account_manifest" {
		title = "AWS account-manifest onboarding report"
	}
	fmt.Fprintln(os.Stdout, title)
	if summary.Host != "" {
		fmt.Fprintf(os.Stdout, "  host:       %s\n", summary.Host)
	}
	if summary.NetworkID != "" {
		fmt.Fprintf(os.Stdout, "  network:    %s\n", summary.NetworkID)
	}
	if summary.AWSOrganizationID != "" {
		fmt.Fprintf(os.Stdout, "  aws org:    %s\n", summary.AWSOrganizationID)
	}
	if summary.AWSManagementID != "" {
		fmt.Fprintf(os.Stdout, "  management: %s\n", summary.AWSManagementID)
	}
	if len(summary.SelectedSetupIDs) > 0 {
		fmt.Fprintf(os.Stdout, "  setup:      %s\n", strings.Join(summary.SelectedSetupIDs, ", "))
	}
	if summary.CredentialMode != "" {
		fmt.Fprintf(os.Stdout, "  credential: %s\n", summary.CredentialMode)
	}
	if len(summary.Regions) > 0 {
		fmt.Fprintf(os.Stdout, "  regions:    %s\n", strings.Join(summary.Regions, ", "))
	}
	fmt.Fprintf(os.Stdout, "  accounts:   %d active", summary.AWSAccountCount)
	if summary.AWSSkippedCount > 0 {
		fmt.Fprintf(os.Stdout, " (%d skipped)", summary.AWSSkippedCount)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "  output:     %s\n", summary.Output)
	if summary.ManualOutput != "" {
		fmt.Fprintf(os.Stdout, "  manual:     %s\n", summary.ManualOutput)
	}
	fmt.Fprintf(os.Stdout, "  post ready: %t\n", summary.CreatePayloadReady)
	fmt.Fprintf(os.Stdout, "  posted:     %d\n", summary.PostedSetupCount)
	if !summary.CreatePayloadReady {
		fmt.Fprintln(os.Stdout, "\nCreate payload contains a placeholder secret. Set AWSSYNC_COLLECTOR_SECRET_ACCESS_KEY or pass --collector-secret-access-key before POSTing.")
	}
	return nil
}

func confirmApply(apply, yes bool, stdin *os.File, stderr io.Writer) error {
	if !apply || yes {
		return nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return fmt.Errorf("--apply requires --yes when stdin is not interactive")
	}
	fmt.Fprint(stderr, "Apply planned AWS setup updates to Forward? Type 'apply' to continue: ")
	var response string
	if _, err := fmt.Fscanln(stdin, &response); err != nil {
		return fmt.Errorf("read apply confirmation: %w", err)
	}
	if response != "apply" {
		return fmt.Errorf("apply cancelled")
	}
	return nil
}

func confirmPost(post, yes bool, setupID string, stdin *os.File, stderr io.Writer) error {
	if !post || yes {
		return nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return fmt.Errorf("--post requires --yes when stdin is not interactive")
	}
	fmt.Fprintf(stderr, "Create new Forward AWS setup %q? Type 'create' to continue: ", setupID)
	var response string
	if _, err := fmt.Fscanln(stdin, &response); err != nil {
		return fmt.Errorf("read create confirmation: %w", err)
	}
	if response != "create" {
		return fmt.Errorf("create cancelled")
	}
	return nil
}

func confirmApplyFromSummary(summary *app.Summary, stdin *os.File, stderr io.Writer) error {
	addedTotal, removedTotal := 0, 0
	for _, setup := range summary.PlannedSetups {
		addedTotal += len(setup.AddedAccounts)
		removedTotal += len(setup.RemovedAccounts)
	}
	fmt.Fprintf(stderr, "Planned changes: add=%d remove=%d.\n", addedTotal, removedTotal)
	if removedTotal > 0 {
		fmt.Fprintln(stderr, "Warning: removes are included. Review setup output carefully.")
	}
	fmt.Fprint(stderr, "Type 'apply' to continue: ")
	var response string
	if _, err := fmt.Fscanln(stdin, &response); err != nil {
		return fmt.Errorf("read apply confirmation: %w", err)
	}
	if response != "apply" {
		return fmt.Errorf("apply cancelled")
	}
	return nil
}

func resolveSetupIDsForCLI(
	ctx context.Context,
	v *viper.Viper,
	password string,
	networkID string,
	setupIDs []string,
	stdin *os.File,
	stderr io.Writer,
) ([]string, error) {
	setupIDs = cleanSetupIDs(setupIDs)
	if len(setupIDs) > 0 {
		client, err := api.NewClient(
			v.GetString("host"),
			v.GetString("api-prefix"),
			v.GetString("username"),
			password,
			v.GetBool("insecure"),
			v.GetDuration("timeout"),
		)
		if err != nil {
			return nil, err
		}
		choices, err := setupChoices(ctx, client, networkID)
		if err != nil {
			return nil, err
		}
		if len(choices) == 0 {
			return nil, newSetupSelectionError(networkID, []string{})
		}
		canonical := make(map[string]string, len(choices))
		for _, choice := range choices {
			key := strings.ToLower(choice)
			if _, ok := canonical[key]; !ok {
				canonical[key] = choice
			}
		}
		resolved := make([]string, 0, len(setupIDs))
		resolvedSet := make(map[string]bool, len(setupIDs))
		invalid := make([]string, 0, len(setupIDs))
		for _, setupID := range setupIDs {
			if canonicalID, ok := canonical[strings.ToLower(setupID)]; ok {
				if resolvedSet[canonicalID] {
					continue
				}
				resolvedSet[canonicalID] = true
				resolved = append(resolved, canonicalID)
				continue
			}
			invalid = append(invalid, setupID)
		}
		if len(invalid) > 0 {
			return nil, newInvalidSetupSelectionError(networkID, canonical, choices, invalid)
		}
		return resolved, nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		client, err := api.NewClient(
			v.GetString("host"),
			v.GetString("api-prefix"),
			v.GetString("username"),
			password,
			v.GetBool("insecure"),
			v.GetDuration("timeout"),
		)
		if err != nil {
			return nil, err
		}
		choices, err := setupChoices(ctx, client, networkID)
		if err != nil {
			return nil, err
		}
		switch len(choices) {
		case 0:
			return nil, newSetupSelectionError(networkID, []string{})
		case 1:
			return choices, nil
		default:
			return nil, newSetupSelectionError(networkID, choices)
		}
	}
	client, err := api.NewClient(
		v.GetString("host"),
		v.GetString("api-prefix"),
		v.GetString("username"),
		password,
		v.GetBool("insecure"),
		v.GetDuration("timeout"),
	)
	if err != nil {
		return nil, err
	}
	choices, err := setupChoices(ctx, client, networkID)
	if err != nil {
		return nil, err
	}
	switch {
	case len(choices) == 0:
		return nil, newSetupSelectionError(networkID, []string{})
	case len(choices) == 1:
		return choices, nil
	}
	return selectSetupIDs(choices, stdin, stderr)
}

func setupChoices(ctx context.Context, client *api.Client, networkID string) ([]string, error) {
	cloudAccounts, err := client.CloudAccounts(ctx, networkID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(cloudAccounts))
	choices := make([]string, 0, len(cloudAccounts))
	for _, account := range cloudAccounts {
		accountType := strings.ToUpper(strings.TrimSpace(account.Type))
		if accountType != "" && accountType != "AWS" {
			continue
		}
		setupID := strings.TrimSpace(account.Name)
		if setupID == "" || seen[setupID] {
			continue
		}
		seen[setupID] = true
		choices = append(choices, setupID)
	}
	sort.Strings(choices)
	return choices, nil
}

func selectSetupIDs(choices []string, reader io.Reader, stderr io.Writer) ([]string, error) {
	fmt.Fprintln(stderr, "Select Forward AWS setup(s):")
	for i, setupID := range choices {
		fmt.Fprintf(stderr, "  %d) %s\n", i+1, setupID)
	}
	fmt.Fprint(stderr, "Enter one or more numbers/IDs (comma-separated), 'all', or blank for all: ")
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read setup selection: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.EqualFold(line, "all") || line == "*" {
		return choices, nil
	}
	tokens := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	selected := make([]string, 0, len(tokens))
	seen := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if index, err := strconv.Atoi(token); err == nil {
			if index < 1 || index > len(choices) {
				return nil, fmt.Errorf("setup selection %q is out of range", token)
			}
			if setupID := choices[index-1]; !seen[setupID] {
				seen[setupID] = true
				selected = append(selected, setupID)
			}
			continue
		}
		for _, setupID := range choices {
			if strings.EqualFold(setupID, token) {
				if !seen[setupID] {
					seen[setupID] = true
					selected = append(selected, setupID)
				}
				goto match
			}
		}
		return nil, fmt.Errorf("setup selection %q does not match a visible setup", token)
	match:
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no setup selected")
	}
	return selected, nil
}

func resolveNetworkIDForCLI(ctx context.Context, v *viper.Viper, password, networkID string, stdin *os.File, stderr io.Writer) (string, error) {
	networkID = strings.TrimSpace(networkID)
	if networkID != "" {
		return networkID, nil
	}
	client, err := api.NewClient(
		v.GetString("host"),
		v.GetString("api-prefix"),
		v.GetString("username"),
		password,
		v.GetBool("insecure"),
		v.GetDuration("timeout"),
	)
	if err != nil {
		return "", err
	}
	return resolveNetworkIDFromClientForCLI(ctx, client, networkID, stdin, stderr)
}

func resolveNetworkIDFromClientForCLI(ctx context.Context, client *api.Client, networkID string, stdin *os.File, stderr io.Writer) (string, error) {
	networkID = strings.TrimSpace(networkID)
	if networkID != "" {
		return networkID, nil
	}
	if !term.IsTerminal(int(stdin.Fd())) {
		return app.ResolveNetworkID(ctx, client, networkID)
	}
	choices, err := app.NetworkChoices(ctx, client)
	if err != nil {
		return "", fmt.Errorf("resolve network ID: %w", err)
	}
	if len(choices) == 1 {
		return choices[0].ID, nil
	}
	return selectNetworkID(choices, stdin, stderr)
}

func selectNetworkID(choices []app.NetworkChoice, reader io.Reader, stderr io.Writer) (string, error) {
	if len(choices) == 0 {
		return "", app.NewNetworkSelectionError(choices)
	}
	if len(choices) == 1 {
		return choices[0].ID, nil
	}
	fmt.Fprintln(stderr, "Select Forward network:")
	for i, choice := range choices {
		if strings.TrimSpace(choice.Name) == "" {
			fmt.Fprintf(stderr, "  %d. %s\n", i+1, choice.ID)
			continue
		}
		fmt.Fprintf(stderr, "  %d. %s  %s\n", i+1, choice.ID, choice.Name)
	}
	fmt.Fprint(stderr, "Enter number or network ID: ")

	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read network selection: %w", err)
	}
	selection := strings.TrimSpace(line)
	if selection == "" {
		return "", fmt.Errorf("network selection cancelled")
	}
	for _, choice := range choices {
		if selection == choice.ID {
			return choice.ID, nil
		}
	}
	if index, err := strconv.Atoi(selection); err == nil {
		if index >= 1 && index <= len(choices) {
			return choices[index-1].ID, nil
		}
		return "", fmt.Errorf("network selection %d is out of range", index)
	}
	return "", fmt.Errorf("network selection %q does not match a visible network", selection)
}

func emitJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}

func emitError(w io.Writer, err error) {
	var setupErr *setupSelectionError
	if errors.As(err, &setupErr) {
		fmt.Fprintln(w, setupErr.Message+".")
		if len(setupErr.Choices) > 0 {
			shown := len(setupErr.Choices)
			if setupErr.Truncated {
				fmt.Fprintf(w, "Visible AWS setups, showing %d of %d:\n", shown, setupErr.Count)
			} else {
				fmt.Fprintf(w, "Visible AWS setups (%d):\n", setupErr.Count)
			}
			for _, choice := range setupErr.Choices {
				fmt.Fprintf(w, "  %s\n", choice)
			}
		}
		if setupErr.UseFlag != "" {
			fmt.Fprintf(w, "\nUse %s.\n", setupErr.UseFlag)
		}
		if len(setupErr.Examples) > 0 {
			fmt.Fprintf(w, "Examples: %s\n", strings.Join(setupErr.Examples, ", "))
		}
		return
	}
	var networkErr *app.NetworkSelectionError
	if errors.As(err, &networkErr) {
		fmt.Fprintln(w, networkErr.Message+".")
		if len(networkErr.Choices) > 0 {
			shown := len(networkErr.Choices)
			if networkErr.Truncated {
				fmt.Fprintf(w, "Visible networks, showing %d of %d:\n", shown, networkErr.Count)
			} else {
				fmt.Fprintf(w, "Visible networks (%d):\n", networkErr.Count)
			}
			for _, choice := range networkErr.Choices {
				if strings.TrimSpace(choice.Name) == "" {
					fmt.Fprintf(w, "  %s\n", choice.ID)
					continue
				}
				fmt.Fprintf(w, "  %s  %s\n", choice.ID, choice.Name)
			}
		}
		if networkErr.UseFlag != "" {
			fmt.Fprintf(w, "\nUse %s.\n", networkErr.UseFlag)
		}
		if len(networkErr.Examples) > 0 {
			fmt.Fprintf(w, "Examples: %s\n", strings.Join(networkErr.Examples, ", "))
		}
		return
	}
	fmt.Fprintln(w, err)
}

type setupSelectionError struct {
	Message   string
	Count     int
	Choices   []string
	Truncated bool
	UseFlag   string
	Examples  []string
}

func (e *setupSelectionError) Error() string {
	return e.Message
}

func newSetupSelectionError(networkID string, choices []string) *setupSelectionError {
	useFlag := "--network-id " + networkID + " --setup-id SETUP_ID"
	if len(choices) == 0 {
		return &setupSelectionError{
			Message: "no Forward AWS setups visible in network " + networkID,
			UseFlag: useFlag,
		}
	}
	examples := make([]string, 0, min(3, len(choices)))
	for _, choice := range choices {
		examples = append(examples, "--setup-id "+choice)
		if len(examples) == 3 {
			break
		}
	}
	visibleChoices := choices
	if len(visibleChoices) > 25 {
		visibleChoices = visibleChoices[:25]
	}
	return &setupSelectionError{
		Message:   "setup IDs are required because this user can see multiple AWS setups in this network",
		Count:     len(choices),
		Choices:   visibleChoices,
		Truncated: len(visibleChoices) < len(choices),
		UseFlag:   useFlag,
		Examples:  examples,
	}
}

func newInvalidSetupSelectionError(networkID string, canonical map[string]string, choices []string, invalid []string) *setupSelectionError {
	examples := make([]string, 0, min(3, len(choices)))
	for _, choice := range choices {
		examples = append(examples, "--setup-id "+choice)
		if len(examples) == 3 {
			break
		}
	}
	visibleChoices := choices
	if len(visibleChoices) > 25 {
		visibleChoices = visibleChoices[:25]
	}
	resolved := make([]string, 0, len(invalid))
	for _, setupID := range invalid {
		setupID = strings.TrimSpace(setupID)
		if setupID == "" {
			continue
		}
		key := strings.ToLower(setupID)
		if _, isKnown := canonical[key]; isKnown {
			continue
		}
		resolved = append(resolved, setupID)
	}
	return &setupSelectionError{
		Message:   fmt.Sprintf("setup IDs do not match visible AWS setups in this network: %s", strings.Join(resolved, ", ")),
		Count:     len(choices),
		Choices:   visibleChoices,
		Truncated: len(visibleChoices) < len(choices),
		UseFlag:   "--network-id " + networkID + " --setup-id SETUP_ID",
		Examples:  examples,
	}
}
