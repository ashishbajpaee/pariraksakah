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

// EDRConnector integrates with endpoint detection & response platforms
// (CrowdStrike Falcon, SentinelOne, etc.).
type EDRConnector struct {
	simulate bool
	apiURL   string
	apiKey   string
	client   *http.Client
}

// NewEDRConnector creates an EDR connector.
func NewEDRConnector(simulate bool) *EDRConnector {
	return &EDRConnector{
		simulate: simulate,
		apiURL:   os.Getenv("EDR_API_URL"),
		apiKey:   os.Getenv("EDR_API_KEY"),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *EDRConnector) Name() string { return "edr" }

func (c *EDRConnector) SupportsRollback(action string) bool {
	return action == "isolate_host" // can un-isolate
}

func (c *EDRConnector) Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error) {
	start := time.Now()

	if c.simulate {
		return c.simulateExecute(action, params, start)
	}
	return c.realExecute(ctx, action, params, start)
}

func (c *EDRConnector) Rollback(ctx context.Context, action string, params map[string]any) error {
	if action != "isolate_host" {
		return fmt.Errorf("edr: rollback not supported for %s", action)
	}
	host, _ := params["host"].(string)
	log.Printf("[EDR] Rolling back isolation for host: %s", host)

	if c.simulate {
		time.Sleep(150 * time.Millisecond)
		log.Printf("[EDR] (simulated) Host %s un-isolated", host)
		return nil
	}

	// Real API call to lift containment
	reqBody, _ := json.Marshal(map[string]string{"host": host, "action": "lift_containment"})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.apiURL+"/hosts/actions/lift-containment", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("edr rollback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("edr rollback HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// ── simulate ────────────────────────────────────

func (c *EDRConnector) simulateExecute(action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	time.Sleep(200 * time.Millisecond)

	switch action {
	case "isolate_host":
		host, _ := params["host"].(string)
		log.Printf("[EDR] (simulated) Isolating host: %s", host)
		return &ActionOutput{
			Fields: map[string]any{
				"host":       host,
				"status":     "isolated",
				"agent_id":   fmt.Sprintf("agent-%s-%d", host, time.Now().Unix()),
				"network":    "quarantine_vlan",
				"edr_action": "contain",
			},
			EvidenceURL: fmt.Sprintf("https://edr.internal/hosts/%s/containment", host),
			Connector:   "edr",
			Simulated:   true,
			Timestamp:   time.Now(),
			DurationMs:  time.Since(start).Milliseconds(),
		}, nil

	case "quarantine_file":
		path, _ := params["path"].(string)
		host, _ := params["host"].(string)
		log.Printf("[EDR] (simulated) Quarantining file %s on %s", path, host)
		return &ActionOutput{
			Fields: map[string]any{
				"file":         path,
				"host":         host,
				"quarantined":  true,
				"sha256":       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"quarantine_id": fmt.Sprintf("qf-%d", time.Now().UnixMilli()),
			},
			EvidenceURL: fmt.Sprintf("https://edr.internal/quarantine/qf-%d", time.Now().UnixMilli()),
			Connector:   "edr",
			Simulated:   true,
			Timestamp:   time.Now(),
			DurationMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	return nil, fmt.Errorf("edr: unknown action %s", action)
}

// ── real API ────────────────────────────────────

func (c *EDRConnector) realExecute(ctx context.Context, action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	var endpoint string
	switch action {
	case "isolate_host":
		endpoint = "/hosts/actions/contain"
	case "quarantine_file":
		endpoint = "/real-time-response/quarantine"
	default:
		return nil, fmt.Errorf("edr: unknown action %s", action)
	}

	reqBody, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("edr request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("edr request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("edr HTTP %d: %s", resp.StatusCode, string(body))
	}

	var fields map[string]any
	_ = json.Unmarshal(body, &fields)

	return &ActionOutput{
		Fields:      fields,
		EvidenceURL: fmt.Sprintf("%s%s?ref=%d", c.apiURL, endpoint, time.Now().UnixMilli()),
		Connector:   "edr",
		Simulated:   false,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
