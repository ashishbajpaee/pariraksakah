package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cybershield-x/incident-response/internal/queue"
)

// QueueHandler serves job queue REST endpoints.
type QueueHandler struct {
	store queue.JobStore
}

// NewQueueHandler creates handlers wired to the job store.
func NewQueueHandler(store queue.JobStore) *QueueHandler {
	return &QueueHandler{store: store}
}

// RegisterRoutes adds queue routes to the given router.
func (h *QueueHandler) RegisterRoutes(r chi.Router) {
	r.Get("/queue/jobs", h.listJobs)
	r.Get("/queue/jobs/{id}", h.getJob)
	r.Post("/queue/jobs/{id}/retry", h.retryJob)
	r.Get("/queue/stats", h.getStats)
	r.Get("/queue/dead-letter", h.listDeadLetter)
}

// GET /queue/jobs
func (h *QueueHandler) listJobs(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	var jobs []*queue.Job
	var err error

	if statusFilter != "" {
		jobs, err = h.store.ListByStatus(queue.Status(statusFilter))
	} else {
		jobs, err = h.store.ListAll()
	}

	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jobs":  jobs,
		"total": len(jobs),
	})
}

// GET /queue/jobs/{id}
func (h *QueueHandler) getJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.store.Get(id)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// POST /queue/jobs/{id}/retry
func (h *QueueHandler) retryJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.RetryDeadLetter(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	log.Printf("[API] Dead-letter job %s re-enqueued via API", id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "re-enqueued",
		"job_id": id,
	})
}

// GET /queue/stats
func (h *QueueHandler) getStats(w http.ResponseWriter, r *http.Request) {
	stats := h.store.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GET /queue/dead-letter
func (h *QueueHandler) listDeadLetter(w http.ResponseWriter, r *http.Request) {
	jobs, err := h.store.ListByStatus(queue.StatusDeadLetter)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dead_letter_jobs": jobs,
		"total":            len(jobs),
	})
}
