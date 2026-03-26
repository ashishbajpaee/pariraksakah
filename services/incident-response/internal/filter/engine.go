package filter

import (
	"log"
	"strings"
)

// FilterResult contains the outcome of evaluating an incident.
type FilterResult struct {
	IsFalsePositive bool
	ConfidenceScore float64
	Reason          string
}

// FilterEngine processes incident parameters to detect false positives.
type FilterEngine struct {
	allowedIPs map[string]string // IP -> Description
}

// NewEngine creates a new FilterEngine initialized with default rules.
func NewEngine() *FilterEngine {
	return &FilterEngine{
		allowedIPs: map[string]string{
			"10.0.0.100":   "Internal Vulnerability Scanner",
			"192.168.1.50": "Authorized Penetration Testing Node",
			"10.0.1.200":   "Scheduled Backup Service",
		},
	}
}

// Evaluate analyzes the incoming incident to determine if it's a false positive.
func (e *FilterEngine) Evaluate(alertType, severity, sourceIP, description string) FilterResult {
	// 1. IP Allowlist Check
	if reason, ok := e.allowedIPs[sourceIP]; ok {
		log.Printf("[FilterEngine] False positive detected: Source IP %s matches allowlist (%s)", sourceIP, reason)
		return FilterResult{
			IsFalsePositive: true,
			ConfidenceScore: 0.95,
			Reason:          "Source IP matches known safe host: " + reason,
		}
	}

	// 2. Description Matching Checks
	descLower := strings.ToLower(description)
	benignKeywords := []struct {
		keyword string
		reason  string
		score   float64
	}{
		{"authorized penetration testing", "Matched authorized pen-test activity", 0.90},
		{"backup process", "Matched expected backup routine", 0.85},
		{"expected traffic", "Matched known expected network behavior", 0.80},
		{"internal heartbeat", "Matched internal system heartbeat", 0.80},
	}

	for _, bk := range benignKeywords {
		if strings.Contains(descLower, bk.keyword) {
			log.Printf("[FilterEngine] False positive detected: Description matches benign keyword '%s'", bk.keyword)
			return FilterResult{
				IsFalsePositive: true,
				ConfidenceScore: bk.score,
				Reason:          bk.reason,
			}
		}
	}

	// 3. Low Severity / Common Noise Check
	// (Example heuristic: if it's an informational alert with certain attributes)
	if severity == "info" && strings.Contains(descLower, "ping sweep") {
		return FilterResult{
			IsFalsePositive: true,
			ConfidenceScore: 0.70,
			Reason:          "Common background noise (Info-level ping sweep)",
		}
	}

	// Default: Treat as genuine threat
	return FilterResult{
		IsFalsePositive: false,
		ConfidenceScore: 0.0,
		Reason:          "No known benign patterns matched",
	}
}
