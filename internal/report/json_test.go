package report

import (
	"bytes"
	"encoding/json"
	"github.com/cnorton-dev/surfacelint/internal/model"
	"testing"
)

func TestPrintJSON(t *testing.T) {
	var b bytes.Buffer
	if err := PrintJSON(&b, model.Result{Target: "example.com", Score: 95}); err != nil {
		t.Fatal(err)
	}
	var got model.Result
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Target != "example.com" || got.Score != 95 {
		t.Fatalf("unexpected result: %#v", got)
	}
}
