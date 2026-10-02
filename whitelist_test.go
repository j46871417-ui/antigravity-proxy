package main

import "testing"

func TestIsHostAllowed(t *testing.T) {
	tests := []struct {
		host    string
		port    int
		allowed bool
	}{
		{"cloudcode-pa.googleapis.com", 443, true},
		{"daily-cloudcode-pa.googleapis.com", 443, true},
		{"ai.google.dev", 443, true},
		{"accounts.google.com", 443, true},
		{"api.anthropic.com", 443, true},
		{"api.openai.com", 443, true},
		{"antigravity-cli-auto-updater-974169037036.us-central1.run.app", 443, true},
		// Zero-Trust verification: arbitrary Cloud Run domains must be blocked
		{"malicious-app.run.app", 443, false},
		{"random.run.app", 443, false},
		// Arbitrary internet hosts must be blocked
		{"example.com", 443, false},
		{"google.com", 443, true},
		{"some.gstatic.com", 443, true},
		{"blocked-port.googleapis.com", 8080, false},
		// Google IP subnets
		{"142.250.180.14", 443, true},
		{"1.1.1.1", 443, false},
		{"8.8.8.8", 443, false},
	}

	for _, tt := range tests {
		got := IsHostAllowed(tt.host, tt.port)
		if got != tt.allowed {
			t.Errorf("IsHostAllowed(%q, %d) = %v; want %v", tt.host, tt.port, got, tt.allowed)
		}
	}
}
