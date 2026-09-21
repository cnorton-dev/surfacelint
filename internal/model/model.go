package model

import "time"

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

type Severity string

const (
	SeverityNone   Severity = "none"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Finding struct {
	ID             string
	Category       string
	Title          string
	Status         Status
	Severity       Severity
	Evidence       string
	Recommendation string
}

type Result struct {
	Target    string
	ScannedAt time.Time
	Duration  time.Duration
	Score     int
	Findings  []Finding
}

func (r Result) Counts() map[Status]int {
	counts := map[Status]int{
		StatusPass: 0,
		StatusWarn: 0,
		StatusFail: 0,
		StatusInfo: 0,
	}
	for _, f := range r.Findings {
		counts[f.Status]++
	}
	return counts
}
