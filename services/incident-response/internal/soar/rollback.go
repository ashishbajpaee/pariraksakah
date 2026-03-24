// Package soar — rollback manager for reversing playbook actions.
package soar

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cybershield-x/incident-response/internal/audit"
	"github.com/cybershield-x/incident-response/internal/soar/connectors"
)

// RollbackRecord stores information needed to undo a single step.
type RollbackRecord struct {
	ExecutionID string
	StepIndex   int
	StepName    string
	Action      string
	Params      map[string]any
	Output      map[string]any
	CanRollback bool
}

// RollbackManager stores reverse actions for completed steps
// and can replay them in reverse order to undo an execution.
type RollbackManager struct {
	mu       sync.RWMutex
	records  map[string][]RollbackRecord // executionID → ordered records
	registry *connectors.Registry
	audit    audit.Store
}

// NewRollbackManager creates a rollback manager wired to connectors and audit.
func NewRollbackManager(reg *connectors.Registry, auditStore audit.Store) *RollbackManager {
	return &RollbackManager{
		records:  make(map[string][]RollbackRecord),
		registry: reg,
		audit:    auditStore,
	}
}

// RecordStep records a completed step so it can be rolled back later.
func (rm *RollbackManager) RecordStep(execID string, stepIndex int, stepName, action string,
	params, output map[string]any) {

	rm.mu.Lock()
	defer rm.mu.Unlock()

	conn, ok := rm.registry.Get(action)
	canRollback := ok && conn.SupportsRollback(action)

	// Merge output into params for rollback (e.g., rule_id from firewall)
	rollbackParams := make(map[string]any)
	for k, v := range params {
		rollbackParams[k] = v
	}
	if output != nil {
		for k, v := range output {
			if _, exists := rollbackParams[k]; !exists {
				rollbackParams[k] = v
			}
		}
	}

	rec := RollbackRecord{
		ExecutionID: execID,
		StepIndex:   stepIndex,
		StepName:    stepName,
		Action:      action,
		Params:      rollbackParams,
		Output:      output,
		CanRollback: canRollback,
	}
	rm.records[execID] = append(rm.records[execID], rec)
	log.Printf("[Rollback] Recorded step %d (%s) for execution %s (rollback=%v)",
		stepIndex, stepName, execID, canRollback)
}

// RollbackExecution reverses all rollback-capable steps for a given execution
// in reverse order. Each rollback action is also recorded in the audit trail.
func (rm *RollbackManager) RollbackExecution(ctx context.Context, execID, incidentID string) error {
	rm.mu.RLock()
	recs, ok := rm.records[execID]
	rm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no records found for execution %s", execID)
	}

	var errs []error
	// Process in reverse
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		if !rec.CanRollback {
			log.Printf("[Rollback] Skipping step %d (%s) — rollback not supported", rec.StepIndex, rec.StepName)
			continue
		}

		log.Printf("[Rollback] Rolling back step %d (%s) action=%s", rec.StepIndex, rec.StepName, rec.Action)

		entry := audit.Entry{
			IncidentID:   incidentID,
			ExecutionID:  execID,
			StepIndex:    rec.StepIndex,
			StepName:     fmt.Sprintf("rollback_%s", rec.StepName),
			Action:       fmt.Sprintf("rollback_%s", rec.Action),
			Actor:        "soar-engine",
			Timestamp:    time.Now().UTC(),
			InputParams:  rec.Params,
			Connector:    "rollback",
			Status:       "success",
		}

		err := rm.registry.Rollback(ctx, rec.Action, rec.Params)
		if err != nil {
			entry.Status = "failed"
			entry.Error = err.Error()
			errs = append(errs, fmt.Errorf("rollback step %d (%s): %w", rec.StepIndex, rec.StepName, err))
		}

		if rm.audit != nil {
			rm.audit.Append(entry)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("rollback completed with %d errors: %v", len(errs), errs)
	}
	return nil
}

// HasRecords returns true if there are rollback records for the execution.
func (rm *RollbackManager) HasRecords(execID string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	_, ok := rm.records[execID]
	return ok
}

// GetRecords returns the rollback records for an execution.
func (rm *RollbackManager) GetRecords(execID string) []RollbackRecord {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	recs := rm.records[execID]
	result := make([]RollbackRecord, len(recs))
	copy(result, recs)
	return result
}
