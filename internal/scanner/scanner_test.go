package scanner

import (
	"testing"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func TestScore(t *testing.T) {
	findings := []model.Finding{
		{Status: model.StatusPass, Severity: model.SeverityNone},
		{Status: model.StatusFail, Severity: model.SeverityHigh},
		{Status: model.StatusWarn, Severity: model.SeverityMedium},
		{Status: model.StatusWarn, Severity: model.SeverityLow},
	}
	if got, want := Score(findings), 82; got != want {
		t.Fatalf("Score()=%d want %d", got, want)
	}
}
