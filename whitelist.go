package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
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
	"x.ai": {},
	"api.x.ai": {},
	"grok.com": {},
	"sora.com": {},
	"cursor.sh": {},
	"api.cursor.sh": {},
	"windsurf.ai": {},
	"api.windsurf.ai": {},
	"codeium.com": {},
	"api.codeium.com": {},
	"githubcopilot.com": {},
	"api.githubcopilot.com": {},
	"perplexity.ai": {},
	"api.perplexity.ai": {},
	"huggingface.co": {},
	"midjourney.com": {},
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
	".x.ai",
	".grok.com",
	".sora.com",
	".cursor.sh",
	".cursor.com",
	".windsurf.ai",
	".codeium.com",
	".githubcopilot.com",
	".perplexity.ai",
	".huggingface.co",
	".midjourney.com",
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

var directBypass = func() bool {
	switch strings.ToLower(strings.TrimSpace(getEnv("PROXY_BYPASS_MODE", "strict"))) {
	case "direct", "bypass", "allow":
		return true
	default:
		return false
	}
}()

var nonPublicNetworks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001::/23", "2001:db8::/32", "2002::/16",
	}
	var networks []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}()

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	if ip.To4() == nil && !ip.Mask(net.CIDRMask(3, 128)).Equal(net.ParseIP("2000::")) {
		return false
	}
	return true
}

func isValidDirectHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// ResolveDirectTargets resolves once and pins connections to public IPs to prevent DNS rebinding.
func ResolveDirectTargets(host string, port int) ([]string, error) {
	if _, ok := allowedPorts[port]; !ok {
		return nil, fmt.Errorf("destination port is not allowed")
	}
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(h); ip != nil {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("destination IP is not public")
		}
		return []string{net.JoinHostPort(ip.String(), strconv.Itoa(port))}, nil
	}
	if !isValidDirectHostname(h) {
		return nil, fmt.Errorf("invalid destination hostname")
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), h)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("destination did not resolve to public IP addresses")
	}
	addrs := make([]string, 0, len(ips))
	for _, result := range ips {
		if !isPublicIP(result.IP) {
			return nil, fmt.Errorf("DNS response contains a non-public IP address")
		}
		addrs = append(addrs, net.JoinHostPort(result.IP.String(), strconv.Itoa(port)))
	}
	return addrs, nil
}

// IsHostAllowed validates the target host and port against Zero-Trust policies.
func IsHostAllowed(host string, port int) bool {
	if _, ok := allowedPorts[port]; !ok {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if _, ok := allowedExactHosts[h]; ok {
		return true
	}
	for _, suffix := range allowedDomainSuffixes {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil && IsGoogleIP(h) {
		return true
	}
	if directBypass {
		if ip := net.ParseIP(h); ip != nil {
			return isPublicIP(ip)
		}
		return isValidDirectHostname(h)
	}
	return false
}
