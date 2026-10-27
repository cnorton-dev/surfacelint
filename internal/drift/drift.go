// Package drift compares security findings from two saved scans.
package drift

import (
	"github.com/cnorton-dev/surfacelint/internal/model"
	"sort"
)

type ChangeKind string

const (
	Added     ChangeKind = "added"
	Removed   ChangeKind = "removed"
	Regressed ChangeKind = "regressed"
	Improved  ChangeKind = "improved"
	Unchanged ChangeKind = "unchanged"
	Changed   ChangeKind = "changed"
)

type Change struct {
	ID     string       `json:"id"`
	Title  string       `json:"title"`
	Kind   ChangeKind   `json:"kind"`
	Before model.Status `json:"before,omitempty"`
	After  model.Status `json:"after,omitempty"`
}

type Comparison struct {
	Target        string   `json:"target"`
	PreviousScore int      `json:"previous_score"`
	CurrentScore  int      `json:"current_score"`
	ScoreDelta    int      `json:"score_delta"`
	Changes       []Change `json:"changes"`
}

func Compare(before, after model.Result) Comparison {
	result := Comparison{Target: after.Target, PreviousScore: before.Score, CurrentScore: after.Score, ScoreDelta: after.Score - before.Score, Changes: make([]Change, 0)}
	prev := make(map[string]model.Finding, len(before.Findings))
	curr := make(map[string]model.Finding, len(after.Findings))
	ids := make(map[string]bool)
	for _, f := range before.Findings {
		prev[f.ID] = f
		ids[f.ID] = true
	}
	for _, f := range after.Findings {
		curr[f.ID] = f
		ids[f.ID] = true
	}
	for id := range ids {
		p, hadPrev := prev[id]
		c, hasCurr := curr[id]
		change := Change{ID: id, Kind: Unchanged}
		switch {
		case !hadPrev:
			change.Kind = Added
			change.Title = c.Title
			change.After = c.Status
		case !hasCurr:
			change.Kind = Removed
			change.Title = p.Title
			change.Before = p.Status
		default:
			change.Title = c.Title
			change.Before = p.Status
			change.After = c.Status
			if p.Status != c.Status {
				prior, current := rank(p.Status), rank(c.Status)
				switch {
				case current > prior:
					change.Kind = Regressed
				case current < prior:
					change.Kind = Improved
				default:
					change.Kind = Changed
				}
			} else if p.Severity != c.Severity || p.Evidence != c.Evidence || p.Recommendation != c.Recommendation {
				change.Kind = Changed
			}
		}
		result.Changes = append(result.Changes, change)
	}
	sort.Slice(result.Changes, func(i, j int) bool { return result.Changes[i].ID < result.Changes[j].ID })
	return result
}
func rank(s model.Status) int {
	switch s {
	case model.StatusFail:
		return 3
	case model.StatusWarn:
		return 2
	case model.StatusInfo:
		return 1
	default:
		return 0
	}
}
