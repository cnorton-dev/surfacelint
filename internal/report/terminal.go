package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func PrintTerminal(w io.Writer, result model.Result) {
	fmt.Fprintf(w, "\nSurfaceLint Security Assessment\n")
	fmt.Fprintf(w, "Target: %s\n", result.Target)
	fmt.Fprintf(w, "Scanned: %s UTC\n", result.ScannedAt.UTC().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "\n")

	category := ""
	for _, f := range result.Findings {
		if f.Category != category {
			category = f.Category
			fmt.Fprintf(w, "%s\n%s\n", category, strings.Repeat("-", len(category)))
		}
		fmt.Fprintf(w, "%s %-32s %s\n", statusMark(f.Status), f.Title, f.Evidence)
	}

	counts := result.Counts()
	fmt.Fprintf(w, "\nSecurity Score: %d/100\n", result.Score)
	fmt.Fprintf(w, "Passed: %d  Warnings: %d  Failed: %d  Info: %d\n",
		counts[model.StatusPass], counts[model.StatusWarn], counts[model.StatusFail], counts[model.StatusInfo])
	fmt.Fprintf(w, "Completed in %s\n", result.Duration.Round(10_000_000))
}

func statusMark(status model.Status) string {
	switch status {
	case model.StatusPass:
		return "[PASS]"
	case model.StatusWarn:
		return "[WARN]"
	case model.StatusFail:
		return "[FAIL]"
	default:
		return "[INFO]"
	}
}
