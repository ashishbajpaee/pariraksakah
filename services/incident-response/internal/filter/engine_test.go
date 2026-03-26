package filter

import (
	"testing"
)

func TestFilterEngine_ScannerIP(t *testing.T) {
	engine := NewEngine()
	
	result := engine.Evaluate("port_scan", "low", "10.0.0.100", "Nmap scan detected")
	if !result.IsFalsePositive {
		t.Errorf("Expected IsFalsePositive to be true for scanner IP 10.0.0.100")
	}
	if result.ConfidenceScore < 0.9 {
		t.Errorf("Expected high confidence score, got %v", result.ConfidenceScore)
	}
	expectedReason := "Source IP matches known safe host: Internal Vulnerability Scanner"
	if result.Reason != expectedReason {
		t.Errorf("Expected reason %q, got %q", expectedReason, result.Reason)
	}
}

func TestFilterEngine_BenignDescription(t *testing.T) {
	engine := NewEngine()
	
	result := engine.Evaluate("data_exfiltration", "high", "192.168.1.10", "Routine nightly backup process moving large files")
	if !result.IsFalsePositive {
		t.Errorf("Expected IsFalsePositive to be true for 'backup process' description")
	}
	if result.ConfidenceScore != 0.85 {
		t.Errorf("Expected confidence score 0.85, got %v", result.ConfidenceScore)
	}
}

func TestFilterEngine_GenuineThreat(t *testing.T) {
	engine := NewEngine()
	
	result := engine.Evaluate("ransomware_detected", "critical", "185.220.101.34", "Ransomware signature T1486 detected")
	if result.IsFalsePositive {
		t.Errorf("Expected IsFalsePositive to be false for genuine threat")
	}
	if result.ConfidenceScore != 0.0 {
		t.Errorf("Expected confidence score 0.0, got %v", result.ConfidenceScore)
	}
}
