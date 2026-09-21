package scanner

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveScan(t *testing.T) {
	if os.Getenv("SURFACELINT_INTEGRATION") != "1" {
		t.Skip("set SURFACELINT_INTEGRATION=1 to run the live network smoke test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := Scan(ctx, "example.com")
	if len(result.Findings) == 0 {
		t.Fatal("live scan returned no findings")
	}
	if result.Score < 0 || result.Score > 100 {
		t.Fatalf("score out of range: %d", result.Score)
	}
}
