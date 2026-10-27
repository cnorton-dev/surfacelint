package main

import (
	"github.com/cnorton-dev/surfacelint/internal/model"
	"testing"
)

func TestThreshold(t *testing.T) {
	result := model.Result{Findings: []model.Finding{{Status: model.StatusWarn}}}
	if reachesThreshold(result, "none") || reachesThreshold(result, "fail") || !reachesThreshold(result, "warn") {
		t.Fatal("wrong warn threshold")
	}
	result.Findings = append(result.Findings, model.Finding{Status: model.StatusFail})
	if !reachesThreshold(result, "fail") || !reachesThreshold(result, "warn") {
		t.Fatal("wrong fail threshold")
	}
}
