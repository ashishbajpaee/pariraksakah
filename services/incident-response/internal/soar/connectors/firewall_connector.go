package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// FirewallConnector integrates with network firewalls
// (Palo Alto, pfSense, iptables wrappers, etc.).
type FirewallConnector struct {
	simulate bool
	apiURL   string
	apiKey   string
	client   *http.Client
}

// NewFirewallConnector creates a firewall connector.
func NewFirewallConnector(simulate bool) *FirewallConnector {
	return &FirewallConnector{
		simulate: simulate,
		apiURL:   os.Getenv("FIREWALL_API_URL"),
		apiKey:   os.Getenv("FIREWALL_API_KEY"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *FirewallConnector) Name() string { return "firewall" }

func (c *FirewallConnector) SupportsRollback(action string) bool {
	return action == "block_ip" // can remove the block rule
}

func (c *FirewallConnector) Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error) {
	start := time.Now()
	if c.simulate {
		return c.simulateExecute(action, params, start)
	}
	return c.realExecute(ctx, action, params, start)
}

func (c *FirewallConnector) Rollback(ctx context.Context, action string, params map[string]any) error {
	ip, _ := params["ip"].(string)
	ruleID, _ := params["rule_id"].(string)
	log.Printf("[Firewall] Rolling back block for IP %s (rule %s)", ip, ruleID)

	if c.simulate {
		time.Sleep(100 * time.Millisecond)
		log.Printf("[Firewall] (simulated) Removed block rule %s for IP %s", ruleID, ip)
		return nil
	}

	reqBody, _ := json.Marshal(map[string]string{"rule_id": ruleID, "action": "remove"})
	req, _ := http.NewRequestWithContext(ctx, "DELETE", c.apiURL+"/rules/"+ruleID, bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("firewall rollback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firewall rollback HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *FirewallConnector) simulateExecute(action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	time.Sleep(150 * time.Millisecond)

	ip, _ := params["ip"].(string)
	ruleID := fmt.Sprintf("fw-rule-%d", time.Now().UnixMilli())

	log.Printf("[Firewall] (simulated) Blocking IP: %s → rule %s", ip, ruleID)
	return &ActionOutput{
		Fields: map[string]any{
			"ip":       ip,
			"rule_id":  ruleID,
			"status":   "blocked",
			"firewall": "applied",
			"acl": map[string]any{
				"direction": "both",
				"protocol":  "any",
				"action":    "deny",
			},
		},
		EvidenceURL: fmt.Sprintf("https://firewall.internal/rules/%s", ruleID),
		Connector:   "firewall",
		Simulated:   true,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

func (c *FirewallConnector) realExecute(ctx context.Context, action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	reqBody, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+"/rules/block", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("firewall request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("firewall request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("firewall HTTP %d: %s", resp.StatusCode, string(body))
	}

	var fields map[string]any
	_ = json.Unmarshal(body, &fields)

	return &ActionOutput{
		Fields:      fields,
		EvidenceURL: fmt.Sprintf("%s/rules/block?ref=%d", c.apiURL, time.Now().UnixMilli()),
		Connector:   "firewall",
		Simulated:   false,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
