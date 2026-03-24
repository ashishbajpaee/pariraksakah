package queue

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// JobStore interface
// ──────────────────────────────────────────────

// JobStore defines persistence operations for the job queue.
type JobStore interface {
	// Enqueue adds a new job to the queue.
	Enqueue(job *Job) error

	// Dequeue atomically claims the next pending job that is due.
	Dequeue() (*Job, error)

	// UpdateStatus updates a job's status and error message.
	UpdateStatus(jobID string, status Status, errMsg string) error

	// SetExecutionID associates a playbook execution ID with a job.
	SetExecutionID(jobID, executionID string) error

	// Get retrieves a job by ID.
	Get(jobID string) (*Job, error)

	// ListByStatus returns all jobs with a given status.
	ListByStatus(status Status) ([]*Job, error)

	// ListAll returns all jobs.
	ListAll() ([]*Job, error)

	// RetryDeadLetter moves a dead-letter job back to pending.
	RetryDeadLetter(jobID string) error

	// Stats returns queue statistics.
	Stats() QueueStats
}

// QueueStats contains queue operational metrics.
type QueueStats struct {
	Pending    int `json:"pending"`
	Running    int `json:"running"`
	Succeeded  int `json:"succeeded"`
	Failed     int `json:"failed"`
	DeadLetter int `json:"dead_letter"`
	Total      int `json:"total"`
}

// ──────────────────────────────────────────────
// In-memory implementation
// ──────────────────────────────────────────────

// MemoryJobStore is a thread-safe in-memory job store.
type MemoryJobStore struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

// NewMemoryJobStore creates a new in-memory job store.
func NewMemoryJobStore() *MemoryJobStore {
	return &MemoryJobStore{
		jobs: make(map[string]*Job),
	}
}

func (s *MemoryJobStore) Enqueue(job *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[job.ID]; exists {
		return fmt.Errorf("job %s already exists", job.ID)
	}
	s.jobs[job.ID] = job
	log.Printf("[JobStore] Enqueued job %s: incident=%s playbook=%s",
		job.ID, job.IncidentID, job.PlaybookName)
	return nil
}

func (s *MemoryJobStore) Dequeue() (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var candidates []*Job
	for _, j := range s.jobs {
		if j.Status == StatusPending && j.NextRunAt.Before(now) {
			candidates = append(candidates, j)
		}
	}
	if len(candidates) == 0 {
		return nil, nil // nothing to dequeue
	}

	// Pick the oldest
	sort.Slice(candidates, func(i, k int) bool {
		return candidates[i].NextRunAt.Before(candidates[k].NextRunAt)
	})
	job := candidates[0]
	job.Status = StatusRunning
	job.Attempt++
	job.UpdatedAt = now
	return job, nil
}

func (s *MemoryJobStore) UpdateStatus(jobID string, status Status, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job %s not found", jobID)
	}
	job.Status = status
	job.Error = errMsg
	job.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *MemoryJobStore) SetExecutionID(jobID, executionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job %s not found", jobID)
	}
	job.ExecutionID = executionID
	return nil
}

func (s *MemoryJobStore) Get(jobID string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job %s not found", jobID)
	}
	return job, nil
}

func (s *MemoryJobStore) ListByStatus(status Status) ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*Job
	for _, j := range s.jobs {
		if j.Status == status {
			result = append(result, j)
		}
	}
	return result, nil
}

func (s *MemoryJobStore) ListAll() ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		result = append(result, j)
	}
	return result, nil
}

func (s *MemoryJobStore) RetryDeadLetter(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job %s not found", jobID)
	}
	if job.Status != StatusDeadLetter {
		return fmt.Errorf("job %s is not in dead_letter status (current: %s)", jobID, job.Status)
	}
	job.Status = StatusPending
	job.Attempt = 0
	job.NextRunAt = time.Now().UTC()
	job.UpdatedAt = time.Now().UTC()
	job.Error = ""
	log.Printf("[JobStore] Dead-letter job %s re-enqueued", jobID)
	return nil
}

func (s *MemoryJobStore) Stats() QueueStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := QueueStats{Total: len(s.jobs)}
	for _, j := range s.jobs {
		switch j.Status {
		case StatusPending:
			stats.Pending++
		case StatusRunning:
			stats.Running++
		case StatusSucceeded:
			stats.Succeeded++
		case StatusFailed:
			stats.Failed++
		case StatusDeadLetter:
			stats.DeadLetter++
		}
	}
	return stats
}
