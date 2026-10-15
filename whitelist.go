package main

import (
	"log"
	"net"
	"strings"
)

var allowedPorts = map[int]struct{}{
	80:   {},
	443:  {},
	5228: {},
}

var allowedExactHosts = map[string]struct{}{
	"cloudcode-pa.googleapis.com":                                {},
	"daily-cloudcode-pa.googleapis.com":                          {},
	"accounts.google.com":                                        {},
	"oauth2.googleapis.com":                                      {},
	"generativelanguage.googleapis.com":                          {},
	"jetski-webchannel.googleapis.com":                           {},
	"storage.googleapis.com":                                     {},
	"antigravity.google":                                         {},
	"antigravity-unleash.goog":                                   {},
	"ai.google.dev":                                              {},
	"www.cloudflare.com":                                         {},
	"chatgpt.com":                                                {},
	"claude.ai":                                                  {},
	"www.google.com":                                             {},
	"myaccount.google.com":                                       {},
	"gemini-api-docs-mcp.dev":                                    {},
	"api.openai.com":                                             {},
	"api.anthropic.com":                                          {},
	"antigravity-cli-auto-updater-974169037036.us-central1.run.app": {},
}

var allowedDomainSuffixes = []string{
	".googleapis.com",
	".googleusercontent.com",
	".gstatic.com",
	".google.com",
	".google",
	".goog",
	".google.dev",
	".openai.com",
	".anthropic.com",
	".claude.ai",
}

var googleCIDRStrings = []string{
	// Legacy AS15169 subnets
	"172.217.0.0/16",
	"142.250.0.0/15",
	"142.251.0.0/16",
	"108.177.0.0/17",
	"209.85.128.0/17",
	"173.194.0.0/16",
	"64.233.160.0/19",
	"74.125.0.0/16",
	"172.253.0.0/16",
	"192.179.0.0/16",
	"216.58.192.0/19",
	"216.239.32.0/19",
	// Google Cloud & Cloud Run IP ranges
	"34.0.0.0/8",
	"35.0.0.0/8",
	"199.36.153.0/24",
	"199.36.158.0/24",
	// Google IPv6 subnets
	"2600:1900::/28",
	"2607:f8b0::/32",
	"2a00:1450::/32",
	"2a04:4e42::/32",
	"2001:4860::/32",
	"2404:6800::/32",
	"2800:3f0::/32",
	"2a02:d340::/32",
}

var parsedGoogleNetworks []*net.IPNet

func init() {
	for _, cidr := range googleCIDRStrings {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[Whitelist] Warning: invalid CIDR %s: %v", cidr, err)
			continue
		}
		parsedGoogleNetworks = append(parsedGoogleNetworks, ipNet)
	}
}

// IsGoogleIP checks if the given IP address string belongs to known Google subnets.
func IsGoogleIP(ipStr string) bool {
	cleanIP := strings.Trim(ipStr, "[]")
	ip := net.ParseIP(cleanIP)
	if ip == nil {
		return false
	}
	for _, netBlock := range parsedGoogleNetworks {
		if netBlock.Contains(ip) {
			return true
		}
	}
	return false
}

// IsHostAllowed validates the target host and port against Zero-Trust policies.
func IsHostAllowed(host string, port int) bool {
	if _, ok := allowedPorts[port]; !ok {
		return false
	}

	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	h = strings.Trim(h, "[]")

	if _, ok := allowedExactHosts[h]; ok {
		return true
	}

	for _, suffix := range allowedDomainSuffixes {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return true
		}
	}

	// Check if target is an IP address
	if len(h) > 0 && (h[0] >= '0' && h[0] <= '9' || strings.Contains(h, ":")) {
		if IsGoogleIP(h) {
			return true
		}
	}

	return false
}
