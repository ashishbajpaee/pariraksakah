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

// TicketingConnector integrates with ticketing/notification platforms
// (Jira, PagerDuty, Slack, etc.).
type TicketingConnector struct {
	simulate bool
	apiURL   string
	apiKey   string
	client   *http.Client
}

// NewTicketingConnector creates a ticketing connector.
func NewTicketingConnector(simulate bool) *TicketingConnector {
	return &TicketingConnector{
		simulate: simulate,
		apiURL:   os.Getenv("TICKETING_API_URL"),
		apiKey:   os.Getenv("TICKETING_API_KEY"),
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *TicketingConnector) Name() string { return "ticketing" }

func (c *TicketingConnector) SupportsRollback(action string) bool {
	return false // tickets/notifications are immutable
}

func (c *TicketingConnector) Rollback(_ context.Context, action string, _ map[string]any) error {
	return fmt.Errorf("ticketing: rollback not supported for %s", action)
}

func (c *TicketingConnector) Execute(ctx context.Context, action string, params map[string]any) (*ActionOutput, error) {
	start := time.Now()
	if c.simulate {
		return c.simulateExecute(action, params, start)
	}
	return c.realExecute(ctx, action, params, start)
}

func (c *TicketingConnector) simulateExecute(action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	time.Sleep(100 * time.Millisecond)

	switch action {
	case "create_ticket":
		title, _ := params["title"].(string)
		ticketID := fmt.Sprintf("JIRA-%d", time.Now().UnixMilli())
		log.Printf("[Ticketing] (simulated) Created ticket %s: %s", ticketID, title)
		return &ActionOutput{
			Fields: map[string]any{
				"ticket_id": ticketID,
				"title":     title,
				"status":    "open",
				"assignee":  "soc-team",
				"priority":  params["priority"],
			},
			EvidenceURL: fmt.Sprintf("https://jira.internal/browse/%s", ticketID),
			Connector:   "ticketing",
			Simulated:   true,
			Timestamp:   time.Now(),
			DurationMs:  time.Since(start).Milliseconds(),
		}, nil

	case "notify":
		channel, _ := params["channel"].(string)
		message, _ := params["message"].(string)
		log.Printf("[Ticketing] (simulated) Notify [%s]: %s", channel, message)
		return &ActionOutput{
			Fields: map[string]any{
				"channel":  channel,
				"notified": true,
				"message":  message,
			},
			Connector:  "ticketing",
			Simulated:  true,
			Timestamp:  time.Now(),
			DurationMs: time.Since(start).Milliseconds(),
		}, nil
	}

	return nil, fmt.Errorf("ticketing: unknown action %s", action)
}

func (c *TicketingConnector) realExecute(ctx context.Context, action string, params map[string]any, start time.Time) (*ActionOutput, error) {
	var endpoint string
	switch action {
	case "create_ticket":
		endpoint = "/rest/api/2/issue"
	case "notify":
		endpoint = "/api/chat.postMessage"
	default:
		return nil, fmt.Errorf("ticketing: unknown action %s", action)
	}

	reqBody, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("ticketing request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ticketing request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ticketing HTTP %d: %s", resp.StatusCode, string(body))
	}

	var fields map[string]any
	_ = json.Unmarshal(body, &fields)

	return &ActionOutput{
		Fields:      fields,
		EvidenceURL: fmt.Sprintf("%s%s?ref=%d", c.apiURL, endpoint, time.Now().UnixMilli()),
		Connector:   "ticketing",
		Simulated:   false,
		Timestamp:   time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}, nil
}
