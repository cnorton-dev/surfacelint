package scanner

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/checks"
	"github.com/cnorton-dev/surfacelint/internal/model"
)

type checkFn func(context.Context, string) []model.Finding

func Scan(ctx context.Context, domain string) model.Result {
	started := time.Now()
	result := model.Result{Target: domain, ScannedAt: started}

	checkers := []checkFn{checks.TLS, checks.HTTP, checks.DNS}
	ch := make(chan []model.Finding, len(checkers))
	var wg sync.WaitGroup
	for _, fn := range checkers {
		wg.Add(1)
		go func(fn checkFn) {
			defer wg.Done()
			ch <- fn(ctx, domain)
		}(fn)
	}
	wg.Wait()
	close(ch)

	for batch := range ch {
		result.Findings = append(result.Findings, batch...)
	}
	sort.SliceStable(result.Findings, func(i, j int) bool {
		if result.Findings[i].Category == result.Findings[j].Category {
			return result.Findings[i].Title < result.Findings[j].Title
		}
		return result.Findings[i].Category < result.Findings[j].Category
	})
	result.Score = Score(result.Findings)
	result.Duration = time.Since(started)
	return result
}

func Score(findings []model.Finding) int {
	score := 100
	for _, f := range findings {
		if f.Status != model.StatusWarn && f.Status != model.StatusFail {
			continue
		}
		penalty := 0
		switch f.Severity {
		case model.SeverityHigh:
			penalty = 12
		case model.SeverityMedium:
			penalty = 7
		case model.SeverityLow:
			penalty = 3
		}
		if f.Status == model.StatusWarn {
			penalty = (penalty + 1) / 2
		}
		score -= penalty
	}
	if score < 0 {
		return 0
	}
	return score
}
