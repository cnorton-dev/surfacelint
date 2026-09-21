package report

import (
	"html/template"
	"os"
	"path/filepath"
	"sort"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

type htmlData struct {
	Result     model.Result
	Counts     map[string]int
	Categories []categoryData
}

type categoryData struct {
	Name     string
	Findings []model.Finding
}

func WriteHTML(path string, result model.Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	groups := map[string][]model.Finding{}
	for _, f := range result.Findings {
		groups[f.Category] = append(groups[f.Category], f)
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	categories := make([]categoryData, 0, len(names))
	for _, name := range names {
		categories = append(categories, categoryData{Name: name, Findings: groups[name]})
	}

	funcs := template.FuncMap{
		"statusClass": func(s model.Status) string { return string(s) },
		"severity":    func(s model.Severity) string { return string(s) },
	}
	t, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rawCounts := result.Counts()
	counts := map[string]int{
		"pass": rawCounts[model.StatusPass],
		"warn": rawCounts[model.StatusWarn],
		"fail": rawCounts[model.StatusFail],
		"info": rawCounts[model.StatusInfo],
	}
	return t.Execute(f, htmlData{Result: result, Counts: counts, Categories: categories})
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SurfaceLint Security Assessment - {{.Result.Target}}</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f4f6f9}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1040px;margin:0 auto;padding:42px 24px 64px}.brand{font-size:14px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:#4e5b73}.hero{display:grid;grid-template-columns:1fr 190px;gap:24px;align-items:center;background:#fff;padding:32px;border-radius:18px;box-shadow:0 8px 30px rgba(24,36,56,.08);margin-top:14px}.hero h1{margin:0 0 7px;font-size:30px}.muted{color:#667085}.score{text-align:center;border-left:1px solid #e7eaf0}.score strong{display:block;font-size:54px;line-height:1}.score span{font-size:13px;color:#667085}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 30px}.metric{background:#fff;border-radius:12px;padding:15px 18px}.metric b{font-size:24px;display:block}.section{margin-top:26px}.section h2{font-size:20px}.finding{background:#fff;border-radius:12px;padding:18px 20px;margin:10px 0;border-left:5px solid #9aa4b2}.finding.pass{border-left-color:#218739}.finding.warn{border-left-color:#b7791f}.finding.fail{border-left-color:#b42318}.finding.info{border-left-color:#3667c8}.topline{display:flex;align-items:center;gap:10px;justify-content:space-between}.title{font-weight:750}.badge{font-size:11px;padding:4px 8px;border-radius:999px;text-transform:uppercase;font-weight:800;letter-spacing:.04em;background:#edf0f4}.evidence{margin-top:9px;color:#475467;line-height:1.5}.recommendation{margin-top:10px;padding:12px 14px;border-radius:8px;background:#f7f8fa;line-height:1.5}.footer{margin-top:32px;color:#7a8496;font-size:12px}.disclaimer{margin-top:18px;padding:14px;border:1px solid #d9dee8;border-radius:10px;color:#667085;font-size:12px;line-height:1.5}@media(max-width:700px){.hero{grid-template-columns:1fr}.score{border-left:0;border-top:1px solid #e7eaf0;padding-top:20px}.summary{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body><main class="wrap">
<div class="brand">SurfaceLint</div>
<section class="hero"><div><h1>Security Assessment</h1><div class="muted">{{.Result.Target}}</div><div class="muted">Scanned {{.Result.ScannedAt.UTC.Format "2006-01-02 15:04:05"}} UTC · Completed in {{.Result.Duration}}</div></div><div class="score"><strong>{{.Result.Score}}</strong><span>SECURITY SCORE / 100</span></div></section>
<section class="summary"><div class="metric"><b>{{index .Counts "pass"}}</b><span class="muted">Passed</span></div><div class="metric"><b>{{index .Counts "warn"}}</b><span class="muted">Warnings</span></div><div class="metric"><b>{{index .Counts "fail"}}</b><span class="muted">Failed</span></div><div class="metric"><b>{{len .Result.Findings}}</b><span class="muted">Checks</span></div></section>
{{range .Categories}}<section class="section"><h2>{{.Name}}</h2>{{range .Findings}}<article class="finding {{statusClass .Status}}"><div class="topline"><div class="title">{{.Title}}</div><div class="badge">{{.Status}}{{if ne (severity .Severity) "none"}} · {{.Severity}}{{end}}</div></div><div class="evidence">{{.Evidence}}</div>{{if .Recommendation}}<div class="recommendation"><strong>Recommendation:</strong> {{.Recommendation}}</div>{{end}}</article>{{end}}</section>{{end}}
<div class="disclaimer">SurfaceLint performs lightweight, non-invasive posture checks using public network and DNS information. Results are informational and are not a substitute for a full security assessment or compliance audit.</div>
<div class="footer">Generated locally by SurfaceLint. No scan results are uploaded by the tool.</div>
</main></body></html>`
