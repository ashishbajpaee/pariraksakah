// Package queue provides production-grade job persistence, queueing,
// and retry with exponential back-off for SOAR playbook executions.
package queue

import (
	"fmt"
	"time"
)

// ──────────────────────────────────────────────
// Job status
// ──────────────────────────────────────────────

// Status represents the lifecycle state of a job.
type Status string

const (
	StatusPending    Status = "pending"
	StatusRunning    Status = "running"
	StatusSucceeded  Status = "succeeded"
	StatusFailed     Status = "failed"
	StatusDeadLetter Status = "dead_letter"
)

// ──────────────────────────────────────────────
// Job
// ──────────────────────────────────────────────

// Job represents a queued playbook execution task.
type Job struct {
	ID           string         `json:"id"`
	IncidentID   string         `json:"incident_id"`
	PlaybookName string         `json:"playbook_name"`
	AlertCtx     map[string]any `json:"alert_ctx"`
	Status       Status         `json:"status"`
	Attempt      int            `json:"attempt"`
	MaxAttempts  int            `json:"max_attempts"`
	NextRunAt    time.Time      `json:"next_run_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	Error        string         `json:"error,omitempty"`
	ExecutionID  string         `json:"execution_id,omitempty"`
}

// NewJob creates a new pending job.
func NewJob(incidentID, playbookName string, alertCtx map[string]any, maxAttempts int) *Job {
	now := time.Now().UTC()
	return &Job{
		ID:           fmt.Sprintf("job-%d", now.UnixMilli()),
		IncidentID:   incidentID,
		PlaybookName: playbookName,
		AlertCtx:     alertCtx,
		Status:       StatusPending,
		Attempt:      0,
		MaxAttempts:  maxAttempts,
		NextRunAt:    now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// BackoffDuration returns the exponential backoff delay for the current attempt.
// Formula: min(2^attempt × 5s, 5min)
func (j *Job) BackoffDuration() time.Duration {
	base := 5 * time.Second
	multiplier := time.Duration(1)
	for i := 0; i < j.Attempt; i++ {
		multiplier *= 2
	}
	d := base * multiplier
	max := 5 * time.Minute
	if d > max {
		return max
	}
	return d
}
