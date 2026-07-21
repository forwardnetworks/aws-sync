package app

import (
	"fmt"
	"strings"
)

type removalStat struct {
	SetupID         string
	ConfiguredCount int
	RemovedCount    int
}

func validateRemovalLimitValues(maxRemovals int, maxRemovalPercent float64) error {
	if maxRemovals < 0 {
		return fmt.Errorf("--max-removals cannot be negative")
	}
	if maxRemovalPercent < 0 || maxRemovalPercent > 100 {
		return fmt.Errorf("--max-removal-percent must be between 0 and 100")
	}
	return nil
}

func validateRemovalStats(stats []removalStat, maxRemovals int, maxRemovalPercent float64) error {
	if err := validateRemovalLimitValues(maxRemovals, maxRemovalPercent); err != nil {
		return err
	}
	problems := make([]string, 0)
	totalRemoved := 0
	for _, stat := range stats {
		totalRemoved += stat.RemovedCount
	}
	if maxRemovals > 0 && totalRemoved > maxRemovals {
		problems = append(problems, fmt.Sprintf(
			"planned removals total %d exceeds --max-removals %d",
			totalRemoved,
			maxRemovals,
		))
	}
	if maxRemovalPercent > 0 {
		for _, stat := range stats {
			if stat.RemovedCount == 0 {
				continue
			}
			percent := 100.0
			if stat.ConfiguredCount > 0 {
				percent = float64(stat.RemovedCount) * 100 / float64(stat.ConfiguredCount)
			}
			if percent > maxRemovalPercent {
				problems = append(problems, fmt.Sprintf(
					"setup %s removes %d of %d accounts (%.2f%%), exceeding --max-removal-percent %.2f",
					stat.SetupID,
					stat.RemovedCount,
					stat.ConfiguredCount,
					percent,
					maxRemovalPercent,
				))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("removal blast-radius check failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

func (p *patchPlan) removalStats() []removalStat {
	stats := make([]removalStat, 0, len(p.Setups))
	for _, setup := range p.Setups {
		stats = append(stats, removalStat{
			SetupID:         setup.SetupID,
			ConfiguredCount: len(setup.CurrentAccounts),
			RemovedCount:    len(setup.RemovedAccounts),
		})
	}
	return stats
}
