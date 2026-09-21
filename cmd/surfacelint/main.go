package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/report"
	"github.com/cnorton-dev/surfacelint/internal/scanner"
	"github.com/cnorton-dev/surfacelint/internal/target"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "surfacelint: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("SurfaceLint %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	reportPath := fs.String("report", "", "HTML report path (default: reports/<domain>-<timestamp>.html)")
	noReport := fs.Bool("no-report", false, "do not write an HTML report")
	timeout := fs.Duration("timeout", 12*time.Second, "overall scan timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: surfacelint scan <domain>")
	}

	domain, err := target.Normalize(fs.Arg(0))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result := scanner.Scan(ctx, domain)
	report.PrintTerminal(os.Stdout, result)

	if *noReport {
		return nil
	}

	path := *reportPath
	if path == "" {
		stamp := result.ScannedAt.Format("20060102-150405")
		path = filepath.Join("reports", fmt.Sprintf("%s-%s.html", domain, stamp))
	}
	if err := report.WriteHTML(path, result); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	abs, _ := filepath.Abs(path)
	fmt.Printf("\nHTML report: %s\n", abs)
	return nil
}

func printUsage() {
	fmt.Print(`SurfaceLint - local-first security posture assessment

Usage:
  surfacelint scan <domain> [options]
  surfacelint version

Examples:
  surfacelint scan example.com
  surfacelint scan https://example.com --timeout 20s
  surfacelint scan example.com --report ./example-report.html
  surfacelint scan example.com --no-report

Scan options:
  --report PATH      HTML report output path
  --no-report        Skip HTML report generation
  --timeout DURATION Overall scan timeout (default 12s)
`)
}
