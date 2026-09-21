package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func TestWriteHTML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	result := model.Result{
		Target:    "example.com",
		ScannedAt: time.Date(2026, 9, 5, 20, 0, 0, 0, time.UTC),
		Duration:  2 * time.Second,
		Score:     93,
		Findings: []model.Finding{{
			ID:       "test.pass",
			Category: "TLS",
			Title:    "Test finding",
			Status:   model.StatusPass,
			Severity: model.SeverityNone,
			Evidence: "Test evidence",
		}},
	}
	if err := WriteHTML(path, result); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"SurfaceLint", "example.com", "93", "Test finding"} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated report missing %q", want)
		}
	}
}
