package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══ Configuration ═══
var (
	prometheusURL        = env("PROMETHEUS_URL", "http://prometheus:9090")
	chaosEngineURL       = env("CHAOS_ENGINE_URL", "http://chaos-experiment-engine:8020")
	redisAddr            = env("REDIS_HOST", "redis") + ":" + env("REDIS_PORT", "6379")
	currentEnv           = env("CHAOS_ENV", "dev")
	maxExperimentsDev    = envInt("CHAOS_MAX_EXPERIMENTS_DEV", 10)
	maxExperimentsStage  = envInt("CHAOS_MAX_EXPERIMENTS_STAGING", 3)

	sacredServices = map[string]bool{
		"schema-registry": true,
		"timescaledb":     true,
		"prometheus":      true,
		"grafana":         true,
	}

	// In-memory state
	budgetMu     sync.Mutex
	dailyBudget  = map[string]int{} // key: "env:date" → count
	auditLog     []AuditEntry
	auditMu      sync.Mutex
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

// ═══ Structs ═══
type ApproveRequest struct {
	ExperimentID  string `json:"experiment_id"`
	BlastRadius   string `json:"blast_radius"`
	TargetService string `json:"target_service"`
}

type ApproveResponse struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

type AuditEntry struct {
	Action       string `json:"action"`
	Actor        string `json:"actor"`
	ExperimentID string `json:"experiment_id"`
	Outcome      string `json:"outcome"`
	Details      string `json:"details"`
	Timestamp    int64  `json:"timestamp"`
}

// ═══ Guardrail Checks ═══

func checkChaosBudget() (bool, string) {
	budgetMu.Lock()
	defer budgetMu.Unlock()

	key := fmt.Sprintf("%s:%s", currentEnv, time.Now().Format("2006-01-02"))
	count := dailyBudget[key]

	maxExp := maxExperimentsDev
	if currentEnv == "staging" {
		maxExp = maxExperimentsStage
	}

	if count >= maxExp {
		return false, fmt.Sprintf("Daily chaos budget exhausted (%d/%d for %s)", count, maxExp, currentEnv)
	}
	return true, ""
}

func incrementBudget() {
	budgetMu.Lock()
	defer budgetMu.Unlock()
	key := fmt.Sprintf("%s:%s", currentEnv, time.Now().Format("2006-01-02"))
	dailyBudget[key]++
}

func checkHealthGate() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", prometheusURL+"/api/v1/query?query=up", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return true, "" // optimistic fallback
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Result []struct {
				Value []interface{} `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return true, ""
	}

	total := len(result.Data.Result)
	healthy := 0
	for _, r := range result.Data.Result {
		if len(r.Value) > 1 && fmt.Sprint(r.Value[1]) == "1" {
			healthy++
		}
	}

	if total > 0 {
		pct := float64(healthy) / float64(total) * 100
		if pct < 80 {
			return false, fmt.Sprintf("System health %.0f%% < 80%% threshold", pct)
		}
	}
	return true, ""
}

func checkSacredService(service string) (bool, string) {
	if sacredServices[service] {
		return false, fmt.Sprintf("Service '%s' is sacred and permanently blocked from chaos", service)
	}
	return true, ""
}

// ═══ Audit Logger ═══
func writeAudit(action, experimentID, outcome, details string) {
	entry := AuditEntry{
		Action:       action,
		Actor:        "chaos-guardrails",
		ExperimentID: experimentID,
		Outcome:      outcome,
		Details:      details,
		Timestamp:    time.Now().UnixMilli(),
	}
	auditMu.Lock()
	auditLog = append(auditLog, entry)
	// Keep only last 1000 entries in memory
	if len(auditLog) > 1000 {
		auditLog = auditLog[len(auditLog)-1000:]
	}
	auditMu.Unlock()
	log.Printf("[AUDIT] %s | %s | %s | %s", action, experimentID, outcome, details)
}

// ═══ HTTP Handlers ═══
func handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp := ApproveResponse{Approved: true}
	w.Header().Set("Content-Type", "application/json")

	// Check 1: Sacred services
	if ok, reason := checkSacredService(req.TargetService); !ok {
		resp.Approved = false
		resp.Reason = reason
		writeAudit("GUARDRAIL_BLOCK", req.ExperimentID, "blocked", reason)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Check 2: Health gate
	if ok, reason := checkHealthGate(); !ok {
		resp.Approved = false
		resp.Reason = reason
		writeAudit("HEALTH_GATE_BLOCK", req.ExperimentID, "blocked", reason)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Check 3: Budget
	if ok, reason := checkChaosBudget(); !ok {
		resp.Approved = false
		resp.Reason = reason
		writeAudit("BUDGET_BLOCK", req.ExperimentID, "blocked", reason)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Check 4: HIGH blast radius requires logging
	if req.BlastRadius == "high" {
		writeAudit("HIGH_BLAST_WARNING", req.ExperimentID, "approved_with_warning",
			"HIGH blast radius experiment approved — monitor closely")
	}

	// All checks passed
	incrementBudget()
	writeAudit("GUARDRAIL_APPROVED", req.ExperimentID, "approved", "All guardrail checks passed")
	json.NewEncoder(w).Encode(resp)
}

func handleApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse URL: /approval/{experimentID}/{action}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path, expected /approval/{experimentID}/{action}", http.StatusBadRequest)
		return
	}
	experimentID := parts[1]
	action := parts[2]

	w.Header().Set("Content-Type", "application/json")

	if action == "approve" {
		writeAudit("HUMAN_APPROVED", experimentID, "approved", "Manual approval granted")
	} else {
		writeAudit("HUMAN_REJECTED", experimentID, "rejected", "Manual approval denied")
	}
	json.NewEncoder(w).Encode(map[string]string{
		"status":        action + "d",
		"experiment_id": experimentID,
	})
}

func handleKillAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Forward kill to chaos engine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "POST", chaosEngineURL+"/chaos/kill-all", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeAudit("KILL_ALL_FAILED", "system", "failed", err.Error())
		http.Error(w, "Kill signal failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	writeAudit("KILL_ALL", "system", "completed", "Emergency kill switch activated")
	json.NewEncoder(w).Encode(map[string]string{"status": "all_killed"})
}

func handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	writeAudit("AUTO_ROLLBACK", "system", "triggered", "Auto rollback of injected faults")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", chaosEngineURL+"/chaos/kill-all", nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "rollback_triggered"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "chaos-guardrails",
		"env":     currentEnv,
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	budgetMu.Lock()
	key := fmt.Sprintf("%s:%s", currentEnv, time.Now().Format("2006-01-02"))
	count := dailyBudget[key]
	budgetMu.Unlock()

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# HELP chaos_guardrails_budget_used Daily chaos budget consumed\n")
	fmt.Fprintf(w, "# TYPE chaos_guardrails_budget_used gauge\n")
	fmt.Fprintf(w, "chaos_guardrails_budget_used{env=\"%s\"} %d\n", currentEnv, count)
	fmt.Fprintf(w, "# HELP chaos_guardrails_sacred_services Number of sacred services\n")
	fmt.Fprintf(w, "# TYPE chaos_guardrails_sacred_services gauge\n")
	fmt.Fprintf(w, "chaos_guardrails_sacred_services %d\n", len(sacredServices))
}

func handleAuditLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	auditMu.Lock()
	entries := make([]AuditEntry, len(auditLog))
	copy(entries, auditLog)
	auditMu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   len(entries),
		"entries": entries,
	})
}

// ═══ Simple Router ═══
func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/approve", handleApprove)
	mux.HandleFunc("/approval/", handleApproval)
	mux.HandleFunc("/chaos/kill-all", handleKillAll)
	mux.HandleFunc("/rollback", handleRollback)
	mux.HandleFunc("/audit", handleAuditLog)

	port := env("CHAOS_GUARDRAILS_PORT", "8024")
	log.Printf("Chaos Guardrails starting on :%s (env=%s, sacred=%d services)", port, currentEnv, len(sacredServices))
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
