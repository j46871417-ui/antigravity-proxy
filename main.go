package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			return n
		}
	}
	return defaultVal
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[Antigravity] ")

	listenHost := getEnv("PROXY_HOST", "0.0.0.0")
	listenPort := getEnv("PROXY_PORT", getEnv("PORT", "50128"))
	listenAddr := net.JoinHostPort(listenHost, listenPort)

	staticUser := getEnv("PROXY_USER", "antigravity")
	staticPass := getEnv("PROXY_PASS", "secret_pass")
	usersFile := getEnv("USERS_FILE", "users.json")
	trafficFile := getEnv("USER_TRAFFIC_FILE", "user_traffic.json")
	monthlyLimit := getEnvInt64("USER_MONTHLY_SOFT_LIMIT_BYTES", 30*1024*1024*1024) // 30 GB

	certFile := getEnv("CERT_FILE", "")
	keyFile := getEnv("KEY_FILE", "")
	logLevel := getEnv("LOG_LEVEL", "INFO")

	log.Printf("Starting Antigravity Proxy Core v2.0 (Go Native Engine)...")
	log.Printf("Listening on %s (Dual-Mode: Plain CONNECT + TLS)", listenAddr)

	cert, err := GetOrGenerateCert(certFile, keyFile)
	if err != nil {
		log.Fatalf("Fatal TLS configuration error: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	authMgr := NewAuthManager(usersFile, staticUser, staticPass)
	trafficMgr := NewTrafficManager(trafficFile, monthlyLimit)

	stopCh := make(chan struct{})
	trafficMgr.StartFlushLoop(stopCh)

	proxyServer := NewProxyServer(tlsConfig, authMgr, trafficMgr, logLevel)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to bind TCP listener on %s: %v", listenAddr, err)
	}
	defer ln.Close()

	log.Printf("Antigravity Proxy Gateway active on %s (PID: %d)", listenAddr, os.Getpid())

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down gracefully...", sig)
		close(stopCh)
		_ = ln.Close()
		trafficMgr.Flush()
		os.Exit(0)
	}()

	if err := proxyServer.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "Server terminated: %v\n", err)
	}
}
