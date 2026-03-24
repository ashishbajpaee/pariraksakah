// Package connectors provides pluggable adapters for external security
// tools (EDR, firewall, ticketing, threat-intel). Each connector implements
// a common interface, supports real API calls when credentials are
// configured, and falls back to a realistic simulated mode for demo/dev.
package connectors

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Connector interface
// ──────────────────────────────────────────────

// Connector is the common interface every external integration must satisfy.
type Connector interface {
	// Name returns a short identifier such as "edr" or "firewall".
	Name() string

	// Execute performs the action (e.g. isolate host, block IP).
	// It returns structured output map and optionally an evidence URL.
	Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error)

	// Rollback reverses a previously executed action when possible.
	Rollback(ctx context.Context, action string, params map[string]any) error

	// SupportsRollback returns true if the given action can be undone.
	SupportsRollback(action string) bool
}

// ActionOutput is the structured result of a connector execution.
type ActionOutput struct {
	Fields      map[string]any `json:"fields"`
	EvidenceURL string         `json:"evidence_url,omitempty"`
	Connector   string         `json:"connector"`
	Simulated   bool           `json:"simulated"`
	Timestamp   time.Time      `json:"timestamp"`
	DurationMs  int64          `json:"duration_ms"`
}

// ──────────────────────────────────────────────
// Registry
// ──────────────────────────────────────────────

// Registry maps action names to connectors.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector // action → connector
	simulate   bool
}

// NewRegistry creates a connector registry. When simulate is true,
// all connectors use their simulated code path instead of real API calls.
func NewRegistry() *Registry {
	sim := os.Getenv("CONNECTOR_SIMULATE") != "false"
	r := &Registry{
		connectors: make(map[string]Connector),
		simulate:   sim,
	}
	r.registerDefaults()
	return r
}

// IsSimulated reports whether the registry runs in simulation mode.
func (r *Registry) IsSimulated() bool { return r.simulate }

// Register binds one or more action names to a connector.
func (r *Registry) Register(connector Connector, actions ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range actions {
		r.connectors[a] = connector
	}
}

// Get returns the connector for a given action.
func (r *Registry) Get(action string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.connectors[action]
	return c, ok
}

// Execute delegates to the appropriate connector for the given action.
func (r *Registry) Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error) {
	c, ok := r.Get(action)
	if !ok {
		return nil, fmt.Errorf("no connector registered for action %q", action)
	}
	return c.Execute(ctx, action, params)
}

// Rollback delegates to the appropriate connector's rollback.
func (r *Registry) Rollback(ctx context.Context, action string, params map[string]any) error {
	c, ok := r.Get(action)
	if !ok {
		return fmt.Errorf("no connector registered for action %q", action)
	}
	if !c.SupportsRollback(action) {
		return fmt.Errorf("action %q does not support rollback", action)
	}
	return c.Rollback(ctx, action, params)
}

// registerDefaults wires up all built-in connectors.
func (r *Registry) registerDefaults() {
	edr := NewEDRConnector(r.simulate)
	r.Register(edr, "isolate_host", "quarantine_file")

	fw := NewFirewallConnector(r.simulate)
	r.Register(fw, "block_ip")

	ticket := NewTicketingConnector(r.simulate)
	r.Register(ticket, "create_ticket", "notify")

	intel := NewThreatIntelConnector(r.simulate)
	r.Register(intel, "enrich_ioc")

	// Passthrough for actions that don't need external calls
	misc := NewMiscConnector(r.simulate)
	r.Register(misc, "run_script", "snapshot_forensic", "restore_backup",
		"revoke_creds", "vulnerability_scan", "patch",
		"quarantine_email", "block_domain", "endpoint_scan",
		"reset_password", "collect_logs")
}
