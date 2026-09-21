package target

import "testing"

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"example.com":                   "example.com",
		"https://Example.COM/path?q=1":  "example.com",
		"http://sub.example.com:8080/x": "sub.example.com",
		"  https://example.com/  ":      "example.com",
	}
	for input, want := range tests {
		got, err := Normalize(input)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("Normalize(%q)=%q want %q", input, got, want)
		}
	}
}

func TestNormalizeRejectsIP(t *testing.T) {
	if _, err := Normalize("127.0.0.1"); err == nil {
		t.Fatal("expected IP target to be rejected")
	}
}
