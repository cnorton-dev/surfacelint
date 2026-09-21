package checks

import "testing"

func TestParseDMARCPolicy(t *testing.T) {
	tests := map[string]string{
		"v=DMARC1; p=reject; rua=mailto:a@example.com": "reject",
		"v=DMARC1; pct=100; p = quarantine":            "quarantine",
		"v=DMARC1; p=none":                             "none",
		"v=DMARC1; rua=mailto:a@example.com":           "",
	}
	for record, want := range tests {
		if got := ParseDMARCPolicy(record); got != want {
			t.Fatalf("ParseDMARCPolicy(%q)=%q want %q", record, got, want)
		}
	}
}
