package drift

import (
	"github.com/cnorton-dev/surfacelint/internal/model"
	"testing"
)

func TestCompareClassifiesChanges(t *testing.T) {
	old := model.Result{Target: "example.com", Score: 70, Findings: []model.Finding{
		{ID: "a", Title: "Regressing", Status: model.StatusPass},
		{ID: "b", Title: "Improving", Status: model.StatusFail},
		{ID: "c", Title: "Removed", Status: model.StatusWarn},
		{ID: "e", Title: "Unchanged", Status: model.StatusPass},
	}}
	new := model.Result{Target: "example.com", Score: 81, Findings: []model.Finding{
		{ID: "a", Title: "Regressing", Status: model.StatusFail},
		{ID: "b", Title: "Improving", Status: model.StatusWarn},
		{ID: "d", Title: "Added", Status: model.StatusWarn},
		{ID: "e", Title: "Unchanged", Status: model.StatusPass},
	}}
	got := Compare(old, new)
	if got.ScoreDelta != 11 || len(got.Changes) != 5 {
		t.Fatalf("unexpected comparison: %#v", got)
	}
	expected := map[string]ChangeKind{"a": Regressed, "b": Improved, "c": Removed, "d": Added, "e": Unchanged}
	for _, c := range got.Changes {
		if expected[c.ID] != c.Kind {
			t.Errorf("%s: got %s want %s", c.ID, c.Kind, expected[c.ID])
		}
	}
}
