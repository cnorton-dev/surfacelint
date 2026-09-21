package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func TLS(ctx context.Context, domain string) []model.Finding {
	findings := make([]model.Finding, 0, 4)
	conn, err := dialTLS(ctx, domain, &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	}, 5*time.Second)
	if err != nil {
		return []model.Finding{{
			ID: "tls.connection", Category: "TLS", Title: "HTTPS/TLS connection",
			Status: model.StatusFail, Severity: model.SeverityHigh,
			Evidence:       fmt.Sprintf("Could not establish a validated TLS connection: %v", err),
			Recommendation: "Confirm HTTPS is enabled, the certificate chain is valid, and the hostname matches the certificate.",
		}}
	}
	defer conn.Close()
	state := conn.ConnectionState()

	findings = append(findings, model.Finding{
		ID: "tls.connection", Category: "TLS", Title: "Validated TLS connection",
		Status: model.StatusPass, Severity: model.SeverityNone,
		Evidence: fmt.Sprintf("Negotiated %s with %s.", tlsVersion(state.Version), tls.CipherSuiteName(state.CipherSuite)),
	})

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		finding := model.Finding{
			ID: "tls.certificate_expiry", Category: "TLS", Title: "Certificate expiration",
			Status: model.StatusPass, Severity: model.SeverityNone,
			Evidence: fmt.Sprintf("Certificate expires %s (%d days remaining).", cert.NotAfter.UTC().Format("2006-01-02"), days),
		}
		switch {
		case days < 0:
			finding.Status = model.StatusFail
			finding.Severity = model.SeverityHigh
			finding.Recommendation = "Replace the expired certificate immediately."
		case days < 14:
			finding.Status = model.StatusFail
			finding.Severity = model.SeverityHigh
			finding.Recommendation = "Renew the certificate immediately and verify automated renewal."
		case days < 30:
			finding.Status = model.StatusWarn
			finding.Severity = model.SeverityMedium
			finding.Recommendation = "Renew the certificate soon and verify automated renewal is working."
		}
		findings = append(findings, finding)
	}

	supported := supportedTLSVersions(ctx, domain)
	if supported[tls.VersionTLS10] || supported[tls.VersionTLS11] {
		old := []string{}
		if supported[tls.VersionTLS10] {
			old = append(old, "TLS 1.0")
		}
		if supported[tls.VersionTLS11] {
			old = append(old, "TLS 1.1")
		}
		findings = append(findings, model.Finding{
			ID: "tls.legacy_versions", Category: "TLS", Title: "Legacy TLS protocols disabled",
			Status: model.StatusFail, Severity: model.SeverityHigh,
			Evidence:       fmt.Sprintf("Server accepts %s.", strings.Join(old, " and ")),
			Recommendation: "Disable TLS 1.0 and TLS 1.1. Require TLS 1.2 or newer.",
		})
	} else {
		findings = append(findings, model.Finding{
			ID: "tls.legacy_versions", Category: "TLS", Title: "Legacy TLS protocols disabled",
			Status: model.StatusPass, Severity: model.SeverityNone,
			Evidence: "TLS 1.0 and TLS 1.1 were not accepted.",
		})
	}

	modern := []string{}
	if supported[tls.VersionTLS12] {
		modern = append(modern, "TLS 1.2")
	}
	if supported[tls.VersionTLS13] {
		modern = append(modern, "TLS 1.3")
	}
	if len(modern) > 0 {
		findings = append(findings, model.Finding{
			ID: "tls.modern_versions", Category: "TLS", Title: "Modern TLS support",
			Status: model.StatusPass, Severity: model.SeverityNone,
			Evidence: fmt.Sprintf("Accepted modern protocols: %s.", strings.Join(modern, ", ")),
		})
	}
	return findings
}

func supportedTLSVersions(ctx context.Context, domain string) map[uint16]bool {
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	out := make(map[uint16]bool, len(versions))
	for _, version := range versions {
		if ctx.Err() != nil {
			return out
		}
		conn, err := dialTLS(ctx, domain, &tls.Config{
			ServerName:         domain,
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true, // protocol capability probe only; certificate validation is a separate check above
		}, 2*time.Second)
		if err == nil {
			out[version] = true
			conn.Close()
		}
	}
	return out
}

func dialTLS(ctx context.Context, domain string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%x", v)
	}
}
