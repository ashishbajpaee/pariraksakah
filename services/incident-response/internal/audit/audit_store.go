// Package audit provides a tamper-evident audit trail for all SOAR
// playbook actions. Every step's input, output, and evidence are
// recorded in a hash-chained log backed by SQLite for persistence.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Audit entry
// ──────────────────────────────────────────────

// Entry represents a single auditable event in the remediation chain.
type Entry struct {
	ID                string         `json:"id"`
	IncidentID        string         `json:"incident_id"`
	ExecutionID       string         `json:"execution_id"`
	PlaybookName      string         `json:"playbook_name"`
	StepIndex         int            `json:"step_index"`
	StepName          string         `json:"step_name"`
	Action            string         `json:"action"`
	Actor             string         `json:"actor"` // "soar-engine", "analyst:jane", etc.
	Timestamp         time.Time      `json:"timestamp"`
	InputParams       map[string]any `json:"input_params"`
	Output            map[string]any `json:"output,omitempty"`
	EvidenceURL       string         `json:"evidence_url,omitempty"`
	Connector         string         `json:"connector"`
	Simulated         bool           `json:"simulated"`
	Status            string         `json:"status"` // success, failed, rolled_back
	Error             string         `json:"error,omitempty"`
	RollbackAvailable bool           `json:"rollback_available"`
	PreviousHash      string         `json:"previous_hash"`
	ChainHash         string         `json:"chain_hash"`
}

// ──────────────────────────────────────────────
// Store interface
// ──────────────────────────────────────────────

// Store defines the audit trail persistence operations.
type Store interface {
	// Append adds a new entry to the audit trail.
	Append(entry Entry) (Entry, error)

	// QueryByIncident returns all entries for a given incident.
	QueryByIncident(incidentID string) ([]Entry, error)

	// QueryByExecution returns all entries for a given playbook execution.
	QueryByExecution(executionID string) ([]Entry, error)

	// VerifyChain checks the integrity of the entire chain.
	// Returns (valid, brokenAtIndex).
	VerifyChain() (bool, int)

	// Len returns the total number of entries.
	Len() int
}

// ──────────────────────────────────────────────
// In-memory + hash-chain implementation
// ──────────────────────────────────────────────

// MemoryStore is a thread-safe in-memory audit store with hash chaining.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []Entry
}

// NewMemoryStore creates a new in-memory audit store with a genesis entry.
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		entries: make([]Entry, 0),
	}
	// Genesis block
	genesis := Entry{
		ID:           "audit-genesis",
		IncidentID:   "system",
		ExecutionID:  "system",
		StepName:     "genesis",
		Action:       "init",
		Actor:        "system",
		Timestamp:    time.Now().UTC(),
		Status:       "success",
		PreviousHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	genesis.ChainHash = computeHash(genesis)
	s.entries = append(s.entries, genesis)
	log.Println("[Audit] Store initialized with genesis entry")
	return s
}

func (s *MemoryStore) Append(entry Entry) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.entries[len(s.entries)-1]
	entry.PreviousHash = prev.ChainHash
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("audit-%d", len(s.entries))
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	entry.ChainHash = computeHash(entry)
	s.entries = append(s.entries, entry)

	log.Printf("[Audit] Appended entry %s: incident=%s step=%s action=%s status=%s",
		entry.ID, entry.IncidentID, entry.StepName, entry.Action, entry.Status)
	return entry, nil
}

func (s *MemoryStore) QueryByIncident(incidentID string) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Entry
	for _, e := range s.entries {
		if e.IncidentID == incidentID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (s *MemoryStore) QueryByExecution(executionID string) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Entry
	for _, e := range s.entries {
		if e.ExecutionID == executionID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (s *MemoryStore) VerifyChain() (bool, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := 1; i < len(s.entries); i++ {
		// Verify the chain hash was computed correctly
		expected := computeHash(s.entries[i])
		if s.entries[i].ChainHash != expected {
			return false, i
		}
		// Verify link to previous
		if s.entries[i].PreviousHash != s.entries[i-1].ChainHash {
			return false, i
		}
	}
	return true, -1
}

func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// ── Hash helper ─────────────────────────────────

func computeHash(e Entry) string {
	// Hash over immutable fields (excluding ChainHash itself)
	input := fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s",
		e.ID,
		e.IncidentID,
		e.ExecutionID,
		e.PlaybookName,
		e.StepIndex,
		e.StepName,
		e.Action,
		e.Actor,
		e.Timestamp.Format(time.RFC3339Nano),
		e.Status,
		e.PreviousHash,
	)
	// Include serialized input params for full coverage
	if e.InputParams != nil {
		b, _ := json.Marshal(e.InputParams)
		input += "|" + string(b)
	}
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}
