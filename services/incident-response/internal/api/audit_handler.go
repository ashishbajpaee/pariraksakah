// Package api provides HTTP handlers for the audit trail and
// rollback endpoints of the incident response SOAR platform.
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cybershield-x/incident-response/internal/audit"
	"github.com/cybershield-x/incident-response/internal/soar"
)

// AuditHandler serves audit trail and rollback REST endpoints.
type AuditHandler struct {
	store   audit.Store
	rollback *soar.RollbackManager
}

// NewAuditHandler creates handlers wired to the audit store and rollback manager.
func NewAuditHandler(store audit.Store, rb *soar.RollbackManager) *AuditHandler {
	return &AuditHandler{store: store, rollback: rb}
}

// RegisterRoutes adds audit/rollback routes to the given router.
func (h *AuditHandler) RegisterRoutes(r chi.Router) {
	r.Get("/audit/incidents/{id}", h.getIncidentAudit)
	r.Get("/audit/executions/{id}", h.getExecutionAudit)
	r.Get("/audit/chain/verify", h.verifyChain)
	r.Post("/remediation/{execID}/rollback", h.rollbackExecution)
}

// GET /audit/incidents/{id}
func (h *AuditHandler) getIncidentAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entries, err := h.store.QueryByIncident(id)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"incident_id": id,
		"entries":     entries,
		"total":       len(entries),
	})
}

// GET /audit/executions/{id}
func (h *AuditHandler) getExecutionAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entries, err := h.store.QueryByExecution(id)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"execution_id": id,
		"entries":      entries,
		"total":        len(entries),
	})
}

// GET /audit/chain/verify
func (h *AuditHandler) verifyChain(w http.ResponseWriter, r *http.Request) {
	valid, brokenAt := h.store.VerifyChain()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":     valid,
		"broken_at": brokenAt,
		"total_entries": h.store.Len(),
	})
}

// POST /remediation/{execID}/rollback
func (h *AuditHandler) rollbackExecution(w http.ResponseWriter, r *http.Request) {
	execID := chi.URLParam(r, "execID")

	// Extract incident ID from query param or request body
	incidentID := r.URL.Query().Get("incident_id")
	if incidentID == "" {
		// Try to find from existing audit records
		entries, _ := h.store.QueryByExecution(execID)
		if len(entries) > 0 {
			incidentID = entries[0].IncidentID
		}
	}

	if !h.rollback.HasRecords(execID) {
		http.Error(w, `{"error":"no rollback records found for execution"}`, http.StatusNotFound)
		return
	}

	log.Printf("[API] Rollback requested for execution %s (incident %s)", execID, incidentID)

	err := h.rollback.RollbackExecution(r.Context(), execID, incidentID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "partial",
			"message": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "rolled_back",
		"execution_id": execID,
		"incident_id":  incidentID,
	})
}
