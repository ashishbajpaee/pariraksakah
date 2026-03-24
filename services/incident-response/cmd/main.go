// CyberShield-X Incident Response Service — SOAR Engine
// Enhanced with real connector adapters, tamper-evident audit trail,
// rollback support, and production-grade job queue with retry.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cybershield-x/incident-response/internal/api"
	"github.com/cybershield-x/incident-response/internal/audit"
	"github.com/cybershield-x/incident-response/internal/queue"
	"github.com/cybershield-x/incident-response/internal/soar"
	"github.com/cybershield-x/incident-response/internal/soar/connectors"
)

// ── Data models ────────────────────────────────

type Incident struct {
	ID          string            `json:"id"`
	AlertType   string            `json:"alert_type"`
	Severity    string            `json:"severity"`
	SourceIP    string            `json:"source_ip"`
	Host        string            `json:"host"`
	Description string            `json:"description"`
	Status      string            `json:"status"` // open,investigating,contained,resolved
	PlaybookRun *PlaybookExecution `json:"playbook_run,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type PlaybookExecution struct {
	ExecutionID  string         `json:"execution_id"`
	PlaybookName string         `json:"playbook_name"`
	Status       string         `json:"status"` // running,completed,failed
	Steps        []StepResult   `json:"steps"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
}

type StepResult struct {
	Name        string `json:"name"`
	Action      string `json:"action"`
	Status      string `json:"status"` // success,failed,skipped
	Output      string `json:"output"`
	EvidenceURL string `json:"evidence_url,omitempty"`
	Connector   string `json:"connector,omitempty"`
	Elapsed     int64  `json:"elapsed_ms"`
}

type CreateIncidentRequest struct {
	AlertType   string `json:"alert_type"`
	Severity    string `json:"severity"`
	SourceIP    string `json:"source_ip"`
	Host        string `json:"host"`
	Description string `json:"description"`
}

// ── In-memory store ────────────────────────────

var (
	incidents   = make(map[string]*Incident)
	incidentsMu sync.RWMutex
	stats       = map[string]int{
		"total_incidents":  0,
		"auto_contained":  0,
		"resolved":        0,
		"mean_ttr_seconds": 0,
	}
)

// ── Global components ──────────────────────────

var (
	connectorRegistry *connectors.Registry
	auditStore        audit.Store
	rollbackMgr       *soar.RollbackManager
	jobStore          queue.JobStore
	workerPool        *queue.Worker
)

// ── Playbook store ─────────────────────────────

var builtinPlaybooks = map[string][]map[string]string{
	"ransomware_response": {
		{"name": "notify_soc_initial",      "action": "notify",           "detail": "Alert SOC on #soc-critical channel"},
		{"name": "isolate_affected_host",   "action": "isolate_host",     "detail": "Block all inbound/outbound on affected host"},
		{"name": "block_c2_ip",             "action": "block_ip",         "detail": "Add source IP to firewall deny-list"},
		{"name": "snapshot_forensic",       "action": "snapshot_forensic","detail": "Capture memory + disk forensic snapshot"},
		{"name": "enrich_ioc",              "action": "enrich_ioc",       "detail": "Query VirusTotal / OTX for IOC enrichment"},
		{"name": "restore_from_backup",     "action": "restore_backup",   "detail": "Restore clean baseline from last known-good snapshot"},
		{"name": "notify_soc_complete",     "action": "notify",           "detail": "Notify SOC: containment complete, monitoring active"},
	},
	"lateral_movement_response": {
		{"name": "notify_soc",             "action": "notify",        "detail": "Alert SOC — lateral movement detected"},
		{"name": "isolate_source_host",    "action": "isolate_host",  "detail": "Isolate the originating host from the network"},
		{"name": "block_attacker_ip",      "action": "block_ip",      "detail": "Block attacker source IP in firewall"},
		{"name": "enrich_source_ioc",      "action": "enrich_ioc",    "detail": "Enrich source IP via threat intel"},
		{"name": "create_tracking_ticket", "action": "create_ticket",  "detail": "Create Jira tracking ticket for investigation"},
		{"name": "revoke_credentials",     "action": "revoke_creds",  "detail": "Revoke compromised user credentials"},
		{"name": "scan_destination_host",  "action": "vulnerability_scan","detail": "Scan destination host for persistence mechanisms"},
	},
	"data_exfiltration_response": {
		{"name": "notify_soc_exfil",       "action": "notify",            "detail": "Alert SOC — data exfiltration detected"},
		{"name": "block_egress_ip",        "action": "block_ip",          "detail": "Block egress destination IP"},
		{"name": "isolate_source",         "action": "isolate_host",      "detail": "Isolate source host from network"},
		{"name": "quarantine_process",     "action": "quarantine_file",   "detail": "Quarantine the exfiltrating process/file"},
		{"name": "forensic_snapshot",      "action": "snapshot_forensic", "detail": "Capture forensic snapshot of source host"},
		{"name": "collect_network_logs",   "action": "collect_logs",      "detail": "Collect network logs for evidence"},
		{"name": "enrich_dest_ip",         "action": "enrich_ioc",        "detail": "Enrich destination IP via threat intel"},
		{"name": "create_exfil_ticket",    "action": "create_ticket",     "detail": "Create tracking ticket with evidence bundle"},
	},
	"phishing_response": {
		{"name": "quarantine_email",       "action": "quarantine_email","detail": "Pull phishing email from all mailboxes"},
		{"name": "block_sender_domain",    "action": "block_domain",   "detail": "Add sender domain to email blocklist"},
		{"name": "scan_clicked_users",     "action": "endpoint_scan",  "detail": "Run EDR scan on users who opened the email"},
		{"name": "reset_credentials",     "action": "reset_password", "detail": "Force credential reset for exposed users"},
		{"name": "notify_users",          "action": "notify",         "detail": "Send awareness notification to all users"},
	},
	"generic_response": {
		{"name": "notify_soc",     "action": "notify",     "detail": "Alert SOC team"},
		{"name": "enrich_ioc",     "action": "enrich_ioc", "detail": "Enrich indicators via OSINT feeds"},
		{"name": "block_source",   "action": "block_ip",   "detail": "Block source IP in firewall"},
		{"name": "collect_logs",   "action": "collect_logs","detail": "Collect and preserve relevant log evidence"},
	},
}

func selectPlaybook(alertType string) string {
	switch {
	case strings.Contains(alertType, "ransomware"):
		return "ransomware_response"
	case strings.Contains(alertType, "lateral"):
		return "lateral_movement_response"
	case strings.Contains(alertType, "exfiltration") || strings.Contains(alertType, "exfil"):
		return "data_exfiltration_response"
	case strings.Contains(alertType, "phishing"):
		return "phishing_response"
	default:
		return "generic_response"
	}
}

// ── Playbook execution engine (enhanced) ───────

// executePlaybookEnhanced runs a playbook using real connectors,
// records every step in the audit trail, and stores rollback info.
// Returns an execution ID for tracking.
func executePlaybookEnhanced(ctx context.Context, incidentID, playbookName string, alertCtx map[string]any) (string, error) {
	steps := builtinPlaybooks[playbookName]
	if steps == nil {
		return "", fmt.Errorf("playbook %q not found", playbookName)
	}

	executionID := fmt.Sprintf("exec-%d", time.Now().UnixMilli())

	exec := &PlaybookExecution{
		ExecutionID:  executionID,
		PlaybookName: playbookName,
		Status:       "running",
		Steps:        make([]StepResult, 0, len(steps)),
		StartedAt:    time.Now(),
	}

	// Update incident status
	incidentsMu.Lock()
	inc := incidents[incidentID]
	if inc != nil {
		inc.Status = "investigating"
		inc.PlaybookRun = exec
	}
	incidentsMu.Unlock()

	allSuccess := true
	for i, step := range steps {
		t0 := time.Now()
		stepName := step["name"]
		action := step["action"]

		// Execute via connector registry
		output, connErr := connectorRegistry.Execute(ctx, action, alertCtx)

		result := StepResult{
			Name:    stepName,
			Action:  action,
			Elapsed: time.Since(t0).Milliseconds(),
		}

		// Build audit entry
		auditEntry := audit.Entry{
			IncidentID:   incidentID,
			ExecutionID:  executionID,
			PlaybookName: playbookName,
			StepIndex:    i,
			StepName:     stepName,
			Action:       action,
			Actor:        "soar-engine",
			InputParams:  alertCtx,
			Connector:    "unknown",
			Simulated:    connectorRegistry.IsSimulated(),
		}

		if connErr != nil {
			result.Status = "failed"
			result.Output = fmt.Sprintf("⚠ %s — %s", step["detail"], connErr.Error())
			auditEntry.Status = "failed"
			auditEntry.Error = connErr.Error()
			allSuccess = false
		} else {
			result.Status = "success"
			result.Output = fmt.Sprintf("✓ %s — executed successfully", step["detail"])
			result.Connector = output.Connector
			result.EvidenceURL = output.EvidenceURL
			auditEntry.Status = "success"
			auditEntry.Output = output.Fields
			auditEntry.EvidenceURL = output.EvidenceURL
			auditEntry.Connector = output.Connector
			auditEntry.Simulated = output.Simulated

			// Check rollback availability
			conn, ok := connectorRegistry.Get(action)
			auditEntry.RollbackAvailable = ok && conn.SupportsRollback(action)

			// Record for potential rollback
			rollbackMgr.RecordStep(executionID, i, stepName, action, alertCtx, output.Fields)
		}

		// Append to audit trail
		auditStore.Append(auditEntry)

		// Update execution record
		incidentsMu.Lock()
		exec.Steps = append(exec.Steps, result)
		incidentsMu.Unlock()
	}

	now := time.Now()
	incidentsMu.Lock()
	if allSuccess {
		exec.Status = "completed"
	} else {
		exec.Status = "completed_with_errors"
	}
	exec.CompletedAt = &now
	if inc := incidents[incidentID]; inc != nil {
		inc.Status = "contained"
		inc.UpdatedAt = now
	}
	stats["auto_contained"]++
	incidentsMu.Unlock()

	log.Printf("[SOAR] Execution %s for incident %s completed (playbook=%s) in %dms",
		executionID, incidentID, playbookName, time.Since(exec.StartedAt).Milliseconds())

	return executionID, nil
}

// ── HTTP handlers ──────────────────────────────

func createIncident(w http.ResponseWriter, r *http.Request) {
	var req CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	if req.Host == "" {
		req.Host = req.SourceIP
	}

	inc := &Incident{
		ID:          fmt.Sprintf("INC-%d", time.Now().UnixMilli()),
		AlertType:   req.AlertType,
		Severity:    req.Severity,
		SourceIP:    req.SourceIP,
		Host:        req.Host,
		Description: req.Description,
		Status:      "open",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	incidentsMu.Lock()
	incidents[inc.ID] = inc
	stats["total_incidents"]++
	incidentsMu.Unlock()

	// Auto-execute playbook for critical/high incidents via job queue
	if req.Severity == "critical" || req.Severity == "high" {
		playbook := selectPlaybook(req.AlertType)
		alertCtx := map[string]any{
			"host":       req.Host,
			"source_ip":  req.SourceIP,
			"alert_type": req.AlertType,
			"severity":   req.Severity,
		}

		maxAttempts := 3
		job := queue.NewJob(inc.ID, playbook, alertCtx, maxAttempts)
		if err := jobStore.Enqueue(job); err != nil {
			log.Printf("[SOAR] Failed to enqueue job for incident %s: %v", inc.ID, err)
			// Fallback: execute directly
			go executePlaybookEnhanced(context.Background(), inc.ID, playbook, alertCtx)
		} else {
			log.Printf("[SOAR] Enqueued job %s for incident %s (playbook=%s)", job.ID, inc.ID, playbook)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inc)
}

func listIncidents(w http.ResponseWriter, r *http.Request) {
	incidentsMu.RLock()
	defer incidentsMu.RUnlock()

	list := make([]*Incident, 0, len(incidents))
	for _, inc := range incidents {
		list = append(list, inc)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"incidents": list, "total": len(list), "stats": stats})
}

func getIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	incidentsMu.RLock()
	inc, ok := incidents[id]
	incidentsMu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

func executeIncidentPlaybook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	incidentsMu.RLock()
	inc, ok := incidents[id]
	incidentsMu.RUnlock()
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	playbook := selectPlaybook(inc.AlertType)
	alertCtx := map[string]any{
		"host":       inc.Host,
		"source_ip":  inc.SourceIP,
		"alert_type": inc.AlertType,
		"severity":   inc.Severity,
	}

	maxAttempts := 3
	job := queue.NewJob(inc.ID, playbook, alertCtx, maxAttempts)
	if err := jobStore.Enqueue(job); err != nil {
		log.Printf("[SOAR] Failed to enqueue job: %v", err)
		// Fallback: execute directly
		go executePlaybookEnhanced(context.Background(), inc.ID, playbook, alertCtx)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Playbook execution enqueued",
		"playbook": playbook,
		"incident": id,
		"job_id":   job.ID,
	})
}

func listPlaybooks(w http.ResponseWriter, r *http.Request) {
	result := make([]map[string]interface{}, 0)
	for name, steps := range builtinPlaybooks {
		result = append(result, map[string]interface{}{
			"name":       name,
			"step_count": len(steps),
			"triggers":   []string{name},
		})
	}

	// Also check filesystem for yaml playbooks
	playbookDir := "playbooks"
	if entries, err := os.ReadDir(playbookDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
				result = append(result, map[string]interface{}{
					"name":      strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())),
					"file":      e.Name(),
					"type":      "yaml",
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"playbooks": result, "total": len(result)})
}

// ── Main ───────────────────────────────────────

func main() {
	port := os.Getenv("INCIDENT_RESPONSE_PORT")
	if port == "" {
		port = "8004"
	}

	// Initialize components
	connectorRegistry = connectors.NewRegistry()
	auditStore = audit.NewMemoryStore()
	rollbackMgr = soar.NewRollbackManager(connectorRegistry, auditStore)
	jobStore = queue.NewMemoryJobStore()

	log.Printf("[SOAR] Connector simulation mode: %v", connectorRegistry.IsSimulated())

	// Start worker pool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	workerPool = queue.NewWorker(jobStore, executePlaybookEnhanced, auditStore, connectorRegistry, rollbackMgr)
	workerPool.Start(ctx)

	// Router setup
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if req.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	// Health endpoint
	r.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		queueStats := jobStore.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "incident-response",
			"version": "2.0.0",
			"stats":   stats,
			"queue":   queueStats,
			"audit_entries": auditStore.Len(),
			"simulate_mode": connectorRegistry.IsSimulated(),
		})
	})
	r.Handle("/metrics", promhttp.Handler())

	// Core incident endpoints
	r.Post("/incidents", createIncident)
	r.Get("/incidents", listIncidents)
	r.Get("/incidents/{id}", getIncident)
	r.Post("/incidents/{id}/execute", executeIncidentPlaybook)
	r.Get("/playbooks", listPlaybooks)

	// Audit & rollback endpoints
	auditHandler := api.NewAuditHandler(auditStore, rollbackMgr)
	auditHandler.RegisterRoutes(r)

	// Queue endpoints
	queueHandler := api.NewQueueHandler(jobStore)
	queueHandler.RegisterRoutes(r)

	// Graceful shutdown
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		log.Println("[SOAR] Shutdown signal received")
		workerPool.Stop()
		cancel()
		srv.Close()
	}()

	log.Printf("Incident Response SOAR Service v2.0 starting on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	// Keep rand seeded for any remaining random usage
	_ = rand.Int()
}
