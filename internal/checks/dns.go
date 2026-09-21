package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

var dmarcPolicyRE = regexp.MustCompile(`(?i)(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)`)

func DNS(ctx context.Context, domain string) []model.Finding {
	resolver := net.DefaultResolver
	return []model.Finding{
		checkSPF(ctx, resolver, domain),
		checkDMARC(ctx, resolver, domain),
	}
}

func checkSPF(ctx context.Context, resolver *net.Resolver, domain string) model.Finding {
	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return model.Finding{ID: "dns.spf", Category: "Email/DNS", Title: "SPF record", Status: model.StatusWarn, Severity: model.SeverityMedium,
			Evidence: fmt.Sprintf("TXT lookup failed: %v", err), Recommendation: "Verify DNS resolution and publish an SPF record if this domain sends email."}
	}
	spf := []string{}
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
			spf = append(spf, record)
		}
	}
	if len(spf) == 0 {
		return model.Finding{ID: "dns.spf", Category: "Email/DNS", Title: "SPF record", Status: model.StatusWarn, Severity: model.SeverityMedium,
			Evidence: "No v=spf1 TXT record was detected.", Recommendation: "If the domain sends email, publish one SPF record that authorizes legitimate sending services."}
	}
	if len(spf) > 1 {
		return model.Finding{ID: "dns.spf", Category: "Email/DNS", Title: "SPF record", Status: model.StatusFail, Severity: model.SeverityHigh,
			Evidence: fmt.Sprintf("Detected %d SPF records. Multiple SPF records can cause SPF evaluation errors.", len(spf)), Recommendation: "Consolidate SPF mechanisms into a single v=spf1 record."}
	}
	return model.Finding{ID: "dns.spf", Category: "Email/DNS", Title: "SPF record", Status: model.StatusPass, Severity: model.SeverityNone,
		Evidence: "SPF: " + truncate(spf[0], 200)}
}

func checkDMARC(ctx context.Context, resolver *net.Resolver, domain string) model.Finding {
	name := "_dmarc." + domain
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusWarn, Severity: model.SeverityMedium,
				Evidence: "No DMARC record was detected at " + name + ".", Recommendation: "Publish a DMARC record. Start with monitoring if needed, then move toward quarantine or reject after validating legitimate senders."}
		}
		return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusWarn, Severity: model.SeverityMedium,
			Evidence: fmt.Sprintf("DMARC DNS lookup failed: %v", err), Recommendation: "Retry the scan and verify DNS resolution before treating this as a missing DMARC record."}
	}
	for _, record := range records {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=dmarc1") {
			continue
		}
		policy := ParseDMARCPolicy(record)
		switch policy {
		case "reject":
			return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusPass, Severity: model.SeverityNone, Evidence: "DMARC policy is p=reject."}
		case "quarantine":
			return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusPass, Severity: model.SeverityNone, Evidence: "DMARC policy is p=quarantine."}
		case "none":
			return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusWarn, Severity: model.SeverityMedium,
				Evidence: "DMARC is present but uses p=none (monitoring only).", Recommendation: "After confirming legitimate mail sources align with SPF/DKIM, consider progressing toward p=quarantine and then p=reject."}
		default:
			return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusWarn, Severity: model.SeverityMedium,
				Evidence: "A DMARC record exists, but a valid p= policy was not recognized.", Recommendation: "Review the DMARC record syntax and ensure it contains p=none, p=quarantine, or p=reject."}
		}
	}
	return model.Finding{ID: "dns.dmarc", Category: "Email/DNS", Title: "DMARC policy", Status: model.StatusWarn, Severity: model.SeverityMedium,
		Evidence: "TXT records were returned, but no v=DMARC1 record was detected.", Recommendation: "Publish a valid v=DMARC1 record."}
}

func ParseDMARCPolicy(record string) string {
	match := dmarcPolicyRE.FindStringSubmatch(record)
	if len(match) < 2 {
		return ""
	}
	return strings.ToLower(match[1])
}
