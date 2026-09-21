package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func HTTP(ctx context.Context, domain string) []model.Finding {
	findings := []model.Finding{}
	client := &http.Client{Timeout: 6 * time.Second}

	findings = append(findings, checkHTTPSRedirect(ctx, client, domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return append(findings, model.Finding{
			ID: "http.fetch", Category: "HTTP", Title: "HTTPS response",
			Status: model.StatusFail, Severity: model.SeverityHigh, Evidence: err.Error(),
		})
	}
	req.Header.Set("User-Agent", "SurfaceLint/0.1 (+https://github.com/cnorton-dev/surfacelint)")
	resp, err := client.Do(req)
	if err != nil {
		return append(findings, model.Finding{
			ID: "http.fetch", Category: "HTTP", Title: "HTTPS response",
			Status: model.StatusFail, Severity: model.SeverityHigh,
			Evidence:       fmt.Sprintf("HTTPS request failed: %v", err),
			Recommendation: "Verify the site is reachable over HTTPS and that its certificate is valid.",
		})
	}
	defer resp.Body.Close()

	findings = append(findings, model.Finding{
		ID: "http.fetch", Category: "HTTP", Title: "HTTPS response",
		Status: model.StatusPass, Severity: model.SeverityNone,
		Evidence: fmt.Sprintf("Received HTTP %d from %s.", resp.StatusCode, resp.Request.URL.String()),
	})

	findings = append(findings,
		headerFinding(resp, "Strict-Transport-Security", "http.hsts", "HSTS enabled", model.SeverityHigh,
			"Add Strict-Transport-Security after confirming the entire site is HTTPS-only."),
		headerFinding(resp, "Content-Security-Policy", "http.csp", "Content Security Policy", model.SeverityMedium,
			"Define a Content-Security-Policy appropriate for the application to reduce script and content injection risk."),
		headerValueFinding(resp, "X-Content-Type-Options", "nosniff", "http.nosniff", "MIME sniffing protection", model.SeverityMedium,
			"Set X-Content-Type-Options: nosniff."),
		frameProtectionFinding(resp),
		headerFinding(resp, "Referrer-Policy", "http.referrer_policy", "Referrer policy", model.SeverityLow,
			"Set a Referrer-Policy such as strict-origin-when-cross-origin based on application needs."),
		headerFinding(resp, "Permissions-Policy", "http.permissions_policy", "Permissions Policy", model.SeverityLow,
			"Consider a Permissions-Policy that disables browser capabilities the application does not use."),
	)

	return findings
}

func checkHTTPSRedirect(ctx context.Context, baseClient *http.Client, domain string) model.Finding {
	client := *baseClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/", nil)
	req.Header.Set("User-Agent", "SurfaceLint/0.1 (+https://github.com/cnorton-dev/surfacelint)")
	resp, err := client.Do(req)
	if err != nil {
		return model.Finding{
			ID: "http.https_redirect", Category: "HTTP", Title: "HTTP redirects to HTTPS",
			Status: model.StatusWarn, Severity: model.SeverityMedium,
			Evidence:       fmt.Sprintf("Could not verify HTTP redirect behavior: %v", err),
			Recommendation: "Ensure plain HTTP requests are permanently redirected to HTTPS.",
		}
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
		u, err := url.Parse(loc)
		if err == nil && strings.EqualFold(u.Scheme, "https") {
			return model.Finding{
				ID: "http.https_redirect", Category: "HTTP", Title: "HTTP redirects to HTTPS",
				Status: model.StatusPass, Severity: model.SeverityNone,
				Evidence: fmt.Sprintf("HTTP %d redirects to %s.", resp.StatusCode, loc),
			}
		}
	}
	return model.Finding{
		ID: "http.https_redirect", Category: "HTTP", Title: "HTTP redirects to HTTPS",
		Status: model.StatusFail, Severity: model.SeverityHigh,
		Evidence:       fmt.Sprintf("Plain HTTP returned status %d without an HTTPS redirect.", resp.StatusCode),
		Recommendation: "Redirect every HTTP request to the equivalent HTTPS URL.",
	}
}

func headerFinding(resp *http.Response, header, id, title string, severity model.Severity, recommendation string) model.Finding {
	value := strings.TrimSpace(resp.Header.Get(header))
	if value == "" {
		return model.Finding{ID: id, Category: "HTTP", Title: title, Status: model.StatusWarn, Severity: severity,
			Evidence: header + " header was not present.", Recommendation: recommendation}
	}
	return model.Finding{ID: id, Category: "HTTP", Title: title, Status: model.StatusPass, Severity: model.SeverityNone,
		Evidence: fmt.Sprintf("%s: %s", header, truncate(value, 180))}
}

func headerValueFinding(resp *http.Response, header, expected, id, title string, severity model.Severity, recommendation string) model.Finding {
	value := strings.TrimSpace(resp.Header.Get(header))
	if !strings.EqualFold(value, expected) {
		evidence := header + " header was not present."
		if value != "" {
			evidence = fmt.Sprintf("%s was %q.", header, value)
		}
		return model.Finding{ID: id, Category: "HTTP", Title: title, Status: model.StatusWarn, Severity: severity, Evidence: evidence, Recommendation: recommendation}
	}
	return model.Finding{ID: id, Category: "HTTP", Title: title, Status: model.StatusPass, Severity: model.SeverityNone, Evidence: fmt.Sprintf("%s: %s", header, value)}
}

func frameProtectionFinding(resp *http.Response) model.Finding {
	xfo := strings.TrimSpace(resp.Header.Get("X-Frame-Options"))
	csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
	if xfo != "" || strings.Contains(csp, "frame-ancestors") {
		evidence := "Frame embedding is restricted."
		if xfo != "" {
			evidence = "X-Frame-Options: " + xfo
		}
		return model.Finding{ID: "http.frame_protection", Category: "HTTP", Title: "Clickjacking protection", Status: model.StatusPass, Severity: model.SeverityNone, Evidence: evidence}
	}
	return model.Finding{ID: "http.frame_protection", Category: "HTTP", Title: "Clickjacking protection", Status: model.StatusWarn, Severity: model.SeverityMedium,
		Evidence:       "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
		Recommendation: "Restrict framing with CSP frame-ancestors and/or X-Frame-Options where appropriate."}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
