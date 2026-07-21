package app

import (
	"strings"
	"testing"
)

func TestValidateRemovalStatsEnforcesAggregateAndPerSetupLimits(t *testing.T) {
	stats := []removalStat{
		{SetupID: "collect_aws_all_ihsm", ConfiguredCount: 202, RemovedCount: 6},
		{SetupID: "collect_spgi_all_aws", ConfiguredCount: 363, RemovedCount: 21},
	}

	if err := validateRemovalStats(stats, 27, 6); err != nil {
		t.Fatalf("expected boundary limits to pass, got %v", err)
	}
	if err := validateRemovalStats(stats, 26, 0); err == nil || !strings.Contains(err.Error(), "total 27") {
		t.Fatalf("expected aggregate removal limit failure, got %v", err)
	}
	if err := validateRemovalStats(stats, 0, 5); err == nil || !strings.Contains(err.Error(), "collect_spgi_all_aws") {
		t.Fatalf("expected per-setup percentage failure, got %v", err)
	}
}

func TestValidateRemovalLimitValuesRejectsInvalidLimits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxCount   int
		maxPercent float64
	}{
		{name: "negative count", maxCount: -1},
		{name: "negative percent", maxPercent: -0.1},
		{name: "percent over one hundred", maxPercent: 100.1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRemovalLimitValues(tc.maxCount, tc.maxPercent); err == nil {
				t.Fatal("expected invalid removal limit error")
			}
		})
	}
}

func TestPatchPlanRemovalStatsUseCurrentConfiguredCounts(t *testing.T) {
	plan := &patchPlan{Setups: []plannedSetup{
		{
			SetupID:         "setup-a",
			CurrentAccounts: []accountRow{{AccountID: "111"}, {AccountID: "222"}},
			RemovedAccounts: []accountRow{{AccountID: "222"}},
		},
	}}
	stats := plan.removalStats()
	if len(stats) != 1 || stats[0].ConfiguredCount != 2 || stats[0].RemovedCount != 1 {
		t.Fatalf("unexpected removal stats: %#v", stats)
	}
}
