package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := Store{Dir: filepath.Join(dir, "history")}
	recent := model.Result{Target: "example.com", Score: 85, ScannedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), Findings: []model.Finding{{ID: "tls.connection", Status: model.StatusPass}}}
	earlier := model.Result{Target: "example.com", Score: 72, ScannedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	for _, v := range []model.Result{recent, earlier} {
		if err := s.Append(v); err != nil {
			t.Fatal(err)
		}
	}
	data, err := s.List("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 || data[0].Score != 72 || data[1].Score != 85 || data[1].Findings[0].ID != "tls.connection" {
		t.Fatalf("unexpected history: %#v", data)
	}
	info, err := os.Stat(filepath.Join(s.Dir, "example.com.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode %o, want 0600", info.Mode().Perm())
	}
	missing, err := s.List("missing.example")
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing history: %v %v", missing, err)
	}
}

func TestRejectUnsafeFilename(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, domain := range []string{"../escape", "test/example.com", "", ".hidden", "EXAMPLE.com"} {
		if err := s.Append(model.Result{Target: domain}); err == nil {
			t.Fatalf("accepted %q", domain)
		}
	}
}

func TestCorruptEntry(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.Dir, "example.com.jsonl"), []byte("{not-json}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List("example.com"); err == nil {
		t.Fatal("expected parse error")
	}
}
