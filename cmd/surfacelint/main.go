package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/drift"
	"github.com/cnorton-dev/surfacelint/internal/history"
	"github.com/cnorton-dev/surfacelint/internal/model"
	"github.com/cnorton-dev/surfacelint/internal/report"
	"github.com/cnorton-dev/surfacelint/internal/scanner"
	"github.com/cnorton-dev/surfacelint/internal/target"
)

var version = "0.2.0-dev"
var errThresholdExceeded = errors.New("security finding threshold exceeded")

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "history":
		err = runHistory(os.Args[2:])
	case "compare":
		err = runCompare(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("SurfaceLint %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "surfacelint: %v\n", err)
		if errors.Is(err, errThresholdExceeded) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	reportPath := fs.String("report", "", "HTML report path (default: reports/<domain>-<timestamp>.html)")
	noReport := fs.Bool("no-report", false, "do not write an HTML report")
	timeout := fs.Duration("timeout", 12*time.Second, "overall scan timeout")
	format := fs.String("format", "text", "result output: text or json")
	failOn := fs.String("fail-on", "none", "CI failure threshold: none, fail, or warn")
	save := fs.Bool("save", false, "append scan to local history")
	dataDir := fs.String("data-dir", "", "local history directory override")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: surfacelint scan [options] <domain>")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("format must be text or json")
	}
	if *failOn != "none" && *failOn != "fail" && *failOn != "warn" {
		return fmt.Errorf("fail-on must be none, fail, or warn")
	}
	if *noReport && *reportPath != "" {
		return fmt.Errorf("--report and --no-report are mutually exclusive")
	}
	domain, err := target.Normalize(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result := scanner.Scan(ctx, domain)
	if *format == "json" {
		if err := report.PrintJSON(os.Stdout, result); err != nil {
			return err
		}
	} else {
		report.PrintTerminal(os.Stdout, result)
	}
	if *save {
		store, err := newStore(*dataDir)
		if err != nil {
			return err
		}
		if err := store.Append(result); err != nil {
			return fmt.Errorf("save scan: %w", err)
		}
	}
	// JSON remains clean on stdout. Unless explicitly requested, HTML is not created in JSON mode.
	writeHTML := !*noReport && (*format == "text" || *reportPath != "")
	if writeHTML {
		path := *reportPath
		if path == "" {
			path = filepath.Join("reports", fmt.Sprintf("%s-%s.html", domain, result.ScannedAt.Format("20060102-150405")))
		}
		if err := report.WriteHTML(path, result); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		abs, _ := filepath.Abs(path)
		if *format == "json" {
			fmt.Fprintf(os.Stderr, "HTML report: %s\n", abs)
		} else {
			fmt.Printf("\nHTML report: %s\n", abs)
		}
	}
	if reachesThreshold(result, *failOn) {
		return errThresholdExceeded
	}
	return nil
}

func reachesThreshold(r model.Result, threshold string) bool {
	for _, f := range r.Findings {
		if f.Status == model.StatusFail && (threshold == "fail" || threshold == "warn") {
			return true
		}
		if f.Status == model.StatusWarn && threshold == "warn" {
			return true
		}
	}
	return false
}

func newStore(customDir string) (history.Store, error) {
	if strings.TrimSpace(customDir) != "" {
		return history.Store{Dir: customDir}, nil
	}
	dir, err := history.DefaultDir()
	return history.Store{Dir: dir}, err
}

func runHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("data-dir", "", "local history directory override")
	limit := fs.Int("limit", 10, "maximum entries to display")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: surfacelint history [options] <domain>")
	}
	if *limit < 1 {
		return fmt.Errorf("limit must be positive")
	}
	domain, err := target.Normalize(fs.Arg(0))
	if err != nil {
		return err
	}
	store, err := newStore(*dir)
	if err != nil {
		return err
	}
	results, err := store.List(domain)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Printf("No saved scans for %s. Use scan --save first.\n", domain)
		return nil
	}
	start := len(results) - *limit
	if start < 0 {
		start = 0
	}
	fmt.Printf("Scan history for %s (%d saved)\n", domain, len(results))
	for i := len(results) - 1; i >= start; i-- {
		r := results[i]
		counts := r.Counts()
		fmt.Printf("%s  Score: %3d  Passed: %d  Warnings: %d  Failed: %d\n", r.ScannedAt.UTC().Format(time.RFC3339), r.Score, counts[model.StatusPass], counts[model.StatusWarn], counts[model.StatusFail])
	}
	return nil
}

func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("data-dir", "", "local history directory override")
	format := fs.String("format", "text", "comparison output: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: surfacelint compare [options] <domain>")
	}
	if *format != "json" && *format != "text" {
		return fmt.Errorf("format must be text or json")
	}
	domain, err := target.Normalize(fs.Arg(0))
	if err != nil {
		return err
	}
	store, err := newStore(*dir)
	if err != nil {
		return err
	}
	results, err := store.List(domain)
	if err != nil {
		return err
	}
	if len(results) < 2 {
		return fmt.Errorf("need two saved scans to compare; run scan --save twice")
	}
	comparison := drift.Compare(results[len(results)-2], results[len(results)-1])
	if *format == "json" {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(comparison)
	}
	fmt.Printf("SurfaceLint posture comparison: %s\nScore: %d -> %d (%+d)\n", domain, comparison.PreviousScore, comparison.CurrentScore, comparison.ScoreDelta)
	for _, change := range comparison.Changes {
		if change.Kind == drift.Unchanged {
			continue
		}
		fmt.Printf("[%s] %s", strings.ToUpper(string(change.Kind)), change.Title)
		if change.Before != "" && change.After != "" {
			fmt.Printf(" (%s -> %s)", change.Before, change.After)
		}
		fmt.Println()
	}
	return nil
}

func printUsage() {
	fmt.Print(`SurfaceLint - local-first security posture assessment

Usage:
  surfacelint scan [options] <domain>
  surfacelint history [options] <domain>
  surfacelint compare [options] <domain>
  surfacelint version

Examples:
  surfacelint scan --save example.com
  surfacelint scan --format json --no-report --fail-on fail example.com
  surfacelint history example.com
  surfacelint compare --format json example.com

Scan options:
  --report PATH      HTML report output path
  --no-report        Skip HTML report generation
  --timeout DURATION Overall scan timeout (default 12s)
  --format FORMAT    text (default) or json
  --save             Store findings in local JSONL history
  --data-dir PATH    Override local history directory
  --fail-on LEVEL    none (default), fail, or warn; exit 3 on threshold

History options:
  --data-dir PATH    Override local history directory
  --limit N          Maximum entries to display (default 10)

Compare options:
  --data-dir PATH    Override local history directory
  --format FORMAT    text (default) or json
`)
}
