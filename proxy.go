package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type ProxyServer struct {
	tlsConfig  *tls.Config
	authMgr    *AuthManager
	trafficMgr *TrafficManager
	statsMgr   *StatsManager
	logLevel   string
}

func NewProxyServer(tlsConfig *tls.Config, authMgr *AuthManager, trafficMgr *TrafficManager, statsMgr *StatsManager, logLevel string) *ProxyServer {
	return &ProxyServer{
		tlsConfig:  tlsConfig,
		authMgr:    authMgr,
		trafficMgr: trafficMgr,
		statsMgr:   statsMgr,
		logLevel:   strings.ToUpper(logLevel),
	}
}

// Serve accepts connections on listener and routes them according to TLS/Plain protocol sniffing.
func (s *ProxyServer) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			continue
		}
		go s.routeConnection(conn)
	}
}

func (s *ProxyServer) routeConnection(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	br := bufio.NewReaderSize(c, 32768)
	firstByte, err := br.Peek(1)
	if err != nil {
		_ = c.Close()
		return
	}

	clientIP := "unknown"
	if addr := c.RemoteAddr(); addr != nil {
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			clientIP = host
		} else {
			clientIP = addr.String()
		}
	}

	bConn := &bufferedConn{Conn: c, r: br}

	// 0x16 = TLS Handshake ClientHello
	if firstByte[0] == 0x16 {
		tlsConn := tls.Server(bConn, s.tlsConfig)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = c.Close()
			return
		}
		_ = c.SetDeadline(time.Time{})
		s.handleClient(tlsConn, clientIP)
	} else {
		// Check if plain connection starts with PROXY protocol v1
		if peekBytes, err := br.Peek(6); err == nil && string(peekBytes) == "PROXY " {
			if line, err := br.ReadString('\n'); err == nil {
				parts := strings.Fields(line)
				if len(parts) >= 3 && (parts[1] == "TCP4" || parts[1] == "TCP6") {
					clientIP = parts[2]
				}
			}
		}
		s.handleClient(bConn, clientIP)
	}
}

func (s *ProxyServer) handleClient(conn net.Conn, clientIP string) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	clientReader := bufio.NewReaderSize(conn, 32768)

	// Read HTTP headers until \r\n\r\n (capped at 64KB)
	var headerBuf bytes.Buffer
	for {
		line, err := clientReader.ReadBytes('\n')
		if err != nil {
			return
		}
		headerBuf.Write(line)
		if headerBuf.Len() > 65536 {
			return
		}
		if bytes.HasSuffix(headerBuf.Bytes(), []byte("\r\n\r\n")) || bytes.HasSuffix(headerBuf.Bytes(), []byte("\n\n")) {
			break
		}
	}

	// Reset read deadline for the active proxy session
	_ = conn.SetDeadline(time.Time{})

	headerStr := headerBuf.String()
	lines := strings.Split(strings.TrimRight(headerStr, "\r\n"), "\r\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return
	}

	reqParts := strings.Fields(lines[0])
	if len(reqParts) < 2 {
		return
	}
	method := strings.ToUpper(reqParts[0])
	target := reqParts[1]

	headers := make(map[string]string)
	for _, l := range lines[1:] {
		if idx := strings.Index(l, ":"); idx != -1 {
			k := strings.ToLower(strings.TrimSpace(l[:idx]))
			v := strings.TrimSpace(l[idx+1:])
			headers[k] = v
		}
	}

	// Check Proxy-Authorization
	authHeader := headers["proxy-authorization"]
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
		s.sendAuthRequired(conn)
		return
	}

	b64Payload := strings.TrimSpace(authHeader[6:])
	decoded, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		s.sendAuthRequired(conn)
		return
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		s.sendAuthRequired(conn)
		return
	}
	proxyUser, proxyPass := creds[0], creds[1]

	if !s.authMgr.Authenticate(proxyUser, proxyPass) {
		log.Printf("[AUTH] Unauthorized auth attempt for user '%s' from %s", proxyUser, clientIP)
		s.statsMgr.Record(proxyUser, "-", 0, "blocked_auth", 0, 0, 0)
		s.sendAuthRequired(conn)
		return
	}

	// Parse destination host and port
	var targetHost string
	var targetPort int

	if method == "CONNECT" {
		if strings.HasPrefix(target, "[") && strings.Contains(target, "]:") {
			idx := strings.LastIndex(target, "]:")
			targetHost = strings.Trim(target[:idx+1], "[]")
			p, err := strconv.Atoi(target[idx+2:])
			if err != nil {
				targetPort = 443
			} else {
				targetPort = p
			}
		} else if strings.Contains(target, ":") {
			h, pStr, err := net.SplitHostPort(target)
			if err != nil {
				targetHost = target
				targetPort = 443
			} else {
				targetHost = h
				p, err := strconv.Atoi(pStr)
				if err != nil {
					targetPort = 443
				} else {
					targetPort = p
				}
			}
		} else {
			targetHost = strings.Trim(target, "[]")
			targetPort = 443
		}
	} else {
		u, err := url.Parse(target)
		if err == nil && u.Host != "" {
			h, pStr, err := net.SplitHostPort(u.Host)
			if err != nil {
				targetHost = u.Host
				targetPort = 80
			} else {
				targetHost = h
				p, err := strconv.Atoi(pStr)
				if err != nil {
					targetPort = 80
				} else {
					targetPort = p
				}
			}
		} else if hostHdr, ok := headers["host"]; ok {
			h, pStr, err := net.SplitHostPort(hostHdr)
			if err != nil {
				targetHost = hostHdr
				targetPort = 80
			} else {
				targetHost = h
				p, err := strconv.Atoi(pStr)
				if err != nil {
					targetPort = 80
				} else {
					targetPort = p
				}
			}
		} else {
			s.sendError(conn, 400, "Bad Request", "Missing Host Header")
			return
		}
	}

	targetHost = strings.TrimSpace(targetHost)

	// Validate against Zero-Trust Whitelist
	if !IsHostAllowed(targetHost, targetPort) {
		log.Printf("[BLOCKED] %s@%s tried to access unauthorized host %s:%d", proxyUser, clientIP, targetHost, targetPort)
		s.statsMgr.Record(proxyUser, targetHost, targetPort, "blocked_whitelist", 0, 0, 0)
		s.sendForbidden(conn)
		return
	}

	log.Printf("[INFO] Allowed %s %s:%d (%s) from %s", method, targetHost, targetPort, proxyUser, clientIP)

	// Connect upstream
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	upstream, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v", targetAddr, err)
		s.statsMgr.Record(proxyUser, targetHost, targetPort, "error", 0, 0, 0)
		s.sendError(conn, 502, "Bad Gateway", "Connection failed")
		return
	}
	defer upstream.Close()

	if tcpUpstream, ok := upstream.(*net.TCPConn); ok {
		_ = tcpUpstream.SetKeepAlive(true)
		_ = tcpUpstream.SetKeepAlivePeriod(30 * time.Second)
	}

	if method == "CONNECT" {
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		// Forward rewritten plain HTTP request
		u, _ := url.Parse(target)
		path := "/"
		if u != nil {
			if u.Path != "" {
				path = u.Path
			}
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
		}
		var reqBuf bytes.Buffer
		reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
		for k, v := range headers {
			if k != "proxy-authorization" && k != "proxy-connection" {
				reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", strings.Title(k), v))
			}
		}
		reqBuf.WriteString("Connection: close\r\n\r\n")
		_, _ = upstream.Write(reqBuf.Bytes())
	}

	// Bidirectional Zero-Copy relay
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesIn, bytesOut int64
	startTime := time.Now()

	pipe := func(dst io.Writer, src io.Reader, closeWrite func(), isClientToUpstream bool) {
		defer wg.Done()
		defer closeWrite()

		buf := make([]byte, 32768)
		n, _ := io.CopyBuffer(dst, src, buf)
		if isClientToUpstream {
			atomic.AddInt64(&bytesIn, n)
		} else {
			atomic.AddInt64(&bytesOut, n)
		}
		s.trafficMgr.Record(proxyUser, n)
	}

	// Client to Upstream: read from clientReader (which buffers decrypted or plain bytes)
	go pipe(upstream, clientReader, func() {
		if tcpUp, ok := upstream.(*net.TCPConn); ok {
			_ = tcpUp.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}, true)

	// Upstream to Client: write to conn
	go pipe(conn, upstream, func() {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		} else {
			_ = conn.Close()
		}
	}, false)

	wg.Wait()

	durationMs := time.Since(startTime).Milliseconds()
	status := "allowed"
	if bytesIn > 0 && bytesOut == 0 {
		status = "timeout_no_data"
	}
	s.statsMgr.Record(proxyUser, targetHost, targetPort, status, bytesIn, bytesOut, durationMs)
}

func (s *ProxyServer) sendAuthRequired(conn net.Conn) {
	resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"Antigravity Secure Gateway\"\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 32\r\n\r\n" +
		"Proxy Authentication Required.\r\n"
	_, _ = conn.Write([]byte(resp))
}

func (s *ProxyServer) sendForbidden(conn net.Conn) {
	body := "Access Denied: unauthorized host. This proxy is strictly for Google Antigravity.\r\n"
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\n"+
		"Connection: close\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
	_, _ = conn.Write([]byte(resp))
}

func (s *ProxyServer) sendError(conn net.Conn, code int, status, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s\r\n", code, status, len(msg)+2, msg)
	_, _ = conn.Write([]byte(resp))
}
