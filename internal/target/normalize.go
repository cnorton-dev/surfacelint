package target

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target cannot be empty")
	}

	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid target: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid target %q", raw)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		return "", fmt.Errorf("v0.1 expects a DNS hostname, not an IP address")
	}
	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("target must be a fully qualified hostname")
	}
	return host, nil
}
