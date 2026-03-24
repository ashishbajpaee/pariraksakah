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

// ThreatIntelConnector integrates with threat intelligence services
// (VirusTotal, OTX, AbuseIPDB, etc.).
type ThreatIntelConnector struct {
	simulate bool
	apiKey   string
	client   *http.Client
}

// NewThreatIntelConnector creates a threat-intel connector.
func NewThreatIntelConnector(simulate bool) *ThreatIntelConnector {
	return &ThreatIntelConnector{
		simulate: simulate,
		apiKey:   os.Getenv("VIRUSTOTAL_API_KEY"),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *ThreatIntelConnector) Name() string { return "threat_intel" }

func (c *ThreatIntelConnector) SupportsRollback(_ string) bool { return false }

func (c *ThreatIntelConnector) Rollback(_ context.Context, action string, _ map[string]any) error {
	return fmt.Errorf("threat_intel: rollback not applicable for %s", action)
}

func (c *ThreatIntelConnector) Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error) {
	start := time.Now()
	if c.simulate {
		return c.simulateExecute(params, start)
	}
	return c.realExecute(ctx, params, start)
}

func (c *ThreatIntelConnector) simulateExecute(params map[string]any, start time.Time) (*ActionOutput, error) {
	time.Sleep(250 * time.Millisecond)

	ioc, _ := params["ioc"].(string)
	log.Printf("[ThreatIntel] (simulated) Enriching IOC: %s", ioc)

	return &ActionOutput{
		Fields: map[string]any{
			"ioc":             ioc,
			"reputation":      "malicious",
			"confidence":      92,
			"source":          "VirusTotal",
			"positives":       48,
			"total_scanners":  72,
			"first_seen":      "2025-11-02T10:30:00Z",
			"last_seen":       time.Now().UTC().Format(time.RFC3339),
			"tags":            []string{"malware", "c2", "trojan"},
			"related_domains": []string{"evil-c2.example.com", "malware-cdn.test"},
		},
		EvidenceURL: fmt.Sprintf("https://www.virustotal.com/gui/search/%s", ioc),
		Connector:   "threat_intel",
		Simulated:   true,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}

func (c *ThreatIntelConnector) realExecute(ctx context.Context, params map[string]any, start time.Time) (*ActionOutput, error) {
	ioc, _ := params["ioc"].(string)
	vtURL := fmt.Sprintf("https://www.virustotal.com/api/v3/search?query=%s", ioc)

	req, err := http.NewRequestWithContext(ctx, "GET", vtURL, bytes.NewReader(nil))
	if err != nil {
		return nil, fmt.Errorf("threat_intel request build: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threat_intel request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("threat_intel HTTP %d: %s", resp.StatusCode, string(body))
	}

	var fields map[string]any
	_ = json.Unmarshal(body, &fields)

	return &ActionOutput{
		Fields:      fields,
		EvidenceURL: fmt.Sprintf("https://www.virustotal.com/gui/search/%s", ioc),
		Connector:   "threat_intel",
		Simulated:   false,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
