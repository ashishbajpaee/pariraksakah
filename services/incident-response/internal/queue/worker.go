package queue

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cybershield-x/incident-response/internal/audit"
	"github.com/cybershield-x/incident-response/internal/soar"
	"github.com/cybershield-x/incident-response/internal/soar/connectors"
)

// PlaybookExecutor is the function signature the worker calls to run a playbook.
// It matches the enhanced executePlaybook signature from main.go.
type PlaybookExecutor func(ctx context.Context, incidentID, playbookName string, alertCtx map[string]any) (executionID string, err error)

// Worker is a pool of goroutines that dequeue and execute playbook jobs
// with exponential backoff retry and dead-letter promotion.
type Worker struct {
	store       JobStore
	executor    PlaybookExecutor
	auditStore  audit.Store
	registry    *connectors.Registry
	rollbackMgr *soar.RollbackManager
	poolSize    int
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewWorker creates a worker pool.
func NewWorker(store JobStore, executor PlaybookExecutor, auditStore audit.Store,
	registry *connectors.Registry, rollbackMgr *soar.RollbackManager) *Worker {

	poolSize := 4
	if s := os.Getenv("WORKER_POOL_SIZE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			poolSize = n
		}
	}

	return &Worker{
		store:       store,
		executor:    executor,
		auditStore:  auditStore,
		registry:    registry,
		rollbackMgr: rollbackMgr,
		poolSize:    poolSize,
		stopCh:      make(chan struct{}),
	}
}

// Start launches the worker goroutines.
func (w *Worker) Start(ctx context.Context) {
	log.Printf("[Worker] Starting %d workers", w.poolSize)
	for i := 0; i < w.poolSize; i++ {
		w.wg.Add(1)
		go w.loop(ctx, i)
	}
}

// Stop gracefully shuts down workers, waiting for in-flight jobs.
func (w *Worker) Stop() {
	log.Println("[Worker] Shutting down...")
	close(w.stopCh)
	w.wg.Wait()
	log.Println("[Worker] All workers stopped")
}

func (w *Worker) loop(ctx context.Context, workerID int) {
	defer w.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.processOne(ctx, workerID)
		}
	}
}

func (w *Worker) processOne(ctx context.Context, workerID int) {
	job, err := w.store.Dequeue()
	if err != nil {
		log.Printf("[Worker-%d] Dequeue error: %v", workerID, err)
		return
	}
	if job == nil {
		return // nothing pending
	}

	log.Printf("[Worker-%d] Processing job %s (incident=%s playbook=%s attempt=%d/%d)",
		workerID, job.ID, job.IncidentID, job.PlaybookName, job.Attempt, job.MaxAttempts)

	execID, execErr := w.executor(ctx, job.IncidentID, job.PlaybookName, job.AlertCtx)

	if execErr != nil {
		w.handleFailure(job, execErr)
		return
	}

	// Success
	w.store.SetExecutionID(job.ID, execID)
	w.store.UpdateStatus(job.ID, StatusSucceeded, "")
	log.Printf("[Worker-%d] Job %s completed (execution=%s)", workerID, job.ID, execID)

	// Record in audit
	if w.auditStore != nil {
		w.auditStore.Append(audit.Entry{
			IncidentID:   job.IncidentID,
			ExecutionID:  execID,
			PlaybookName: job.PlaybookName,
			StepName:     "job_completed",
			Action:       "queue_success",
			Actor:        fmt.Sprintf("worker-%d", workerID),
			Status:       "success",
			Connector:    "queue",
		})
	}
}

func (w *Worker) handleFailure(job *Job, execErr error) {
	errMsg := execErr.Error()
	log.Printf("[Worker] Job %s failed (attempt %d/%d): %s",
		job.ID, job.Attempt, job.MaxAttempts, errMsg)

	if job.Attempt >= job.MaxAttempts {
		// Promote to dead letter
		w.store.UpdateStatus(job.ID, StatusDeadLetter, errMsg)
		log.Printf("[Worker] Job %s promoted to dead_letter after %d attempts", job.ID, job.Attempt)

		// Send alert notification for dead-letter jobs
		if w.registry != nil {
			out, _ := w.registry.Execute(context.Background(), "notify", map[string]any{
				"channel": "#soc-dead-letter",
				"message": fmt.Sprintf("⚠️ Job %s (incident %s) failed after %d attempts: %s",
					job.ID, job.IncidentID, job.Attempt, errMsg),
			})
			_ = out
		}
		return
	}

	// Schedule retry with exponential backoff
	job.NextRunAt = time.Now().UTC().Add(job.BackoffDuration())
	w.store.UpdateStatus(job.ID, StatusPending, errMsg)
	log.Printf("[Worker] Job %s scheduled for retry at %s (backoff=%s)",
		job.ID, job.NextRunAt.Format(time.RFC3339), job.BackoffDuration())
}
