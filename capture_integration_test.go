package main

import (
	stdbufio "bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTrafficCaptureEndToEnd(t *testing.T) {
	oldConfig, oldParent, oldSite := config, parentProxy, siteStat
	oldListen, oldSelfListen := listenProxy, selfListenAddr
	oldTLSConfig := newCaptureUpstreamTLSConfig
	oldDialTimeout, oldReadTimeout := dialTimeout, readTimeout
	defer func() {
		config, parentProxy, siteStat = oldConfig, oldParent, oldSite
		listenProxy, selfListenAddr = oldListen, oldSelfListen
		newCaptureUpstreamTLSConfig = oldTLSConfig
		dialTimeout, readTimeout = oldDialTimeout, oldReadTimeout
	}()

	dir := t.TempDir()
	initConfig(filepath.Join(dir, "rc"))
	config.Capture = true
	config.CaptureDir = filepath.Join(dir, "capture")
	config.CaptureDomainFile = filepath.Join(dir, "domain.list")
	if err := os.WriteFile(config.CaptureDomainFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config.DialTimeout = 3 * time.Second
	config.ReadTimeout = 3 * time.Second
	config.TunnelTimeout = 3 * time.Second
	config.saveReqLine = false
	dialTimeout, readTimeout = config.DialTimeout, config.ReadTimeout
	parentProxy = &backupParentPool{}
	siteStat = newSiteStat()
	if err := initCapture(); err != nil {
		t.Fatal(err)
	}

	plainServer := httptest.NewServer(nethttp.HandlerFunc(captureTestHandler))
	defer plainServer.Close()
	tlsServer := httptest.NewTLSServer(nethttp.HandlerFunc(captureTestHandler))
	defer tlsServer.Close()
	upstreamRoots := x509.NewCertPool()
	upstreamCert, err := x509.ParseCertificate(tlsServer.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	upstreamRoots.AddCert(upstreamCert)
	newCaptureUpstreamTLSConfig = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, RootCAs: upstreamRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	}

	proxyURL, stopProxy := startCaptureTestProxy(t)
	defer stopProxy()
	listenProxy = []Proxy{newHttpProxy(proxyURL.Host, "")}
	initSelfListenAddr()
	caResponse, err := nethttp.Get(proxyURL.String() + captureCAURLPath)
	if err != nil {
		t.Fatalf("download capture CA: %v", err)
	}
	downloadedCA, err := io.ReadAll(caResponse.Body)
	_ = caResponse.Body.Close()
	if err != nil || caResponse.StatusCode != nethttp.StatusOK || string(downloadedCA) != string(captureCA.certPEM) {
		t.Fatalf("download capture CA: status=%d err=%v", caResponse.StatusCode, err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(captureCA.cert)
	transport := &nethttp.Transport{
		Proxy:             nethttp.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: rootPool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	client := &nethttp.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, tc := range []struct {
		url, request, response string
	}{
		{plainServer.URL + "/plain.json", "plain-request", "plain-response"},
		{tlsServer.URL + "/secure.json", "secure-request", "secure-response"},
	} {
		resp, err := client.Post(tc.url, "text/plain", strings.NewReader(tc.request))
		if err != nil {
			t.Fatalf("POST %s: %v", tc.url, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(body) != tc.response {
			t.Fatalf("POST %s: body=%q err=%v", tc.url, body, err)
		}
	}
	transport.CloseIdleConnections()

	webSocketExchange(t, proxyURL.Host, strings.Replace(plainServer.URL, "http://", "ws://", 1)+"/plain-socket", nil, "ws-request", "ws-response")
	webSocketExchange(t, proxyURL.Host, strings.Replace(tlsServer.URL, "https://", "wss://", 1)+"/secure-socket", rootPool, "wss-request", "wss-response")
	socksAddr, stopSOCKS := startCaptureTestSOCKSProxy(t)
	defer stopSOCKS()
	httpExchangeSOCKS(t, socksAddr, plainServer.URL+"/socks-plain.json", nil, "socks-http-request", "socks-http-response")
	httpExchangeSOCKS(t, socksAddr, tlsServer.URL+"/socks-secure.json", rootPool, "socks-https-request", "socks-https-response")
	webSocketExchangeSOCKS(t, socksAddr, strings.Replace(plainServer.URL, "http://", "ws://", 1)+"/socks-plain-socket", nil, "socks-ws-request", "socks-ws-response")
	webSocketExchangeSOCKS(t, socksAddr, strings.Replace(tlsServer.URL, "https://", "wss://", 1)+"/socks-secure-socket", rootPool, "socks-wss-request", "socks-wss-response")
	echoAddr, stopEcho := startCaptureTestEchoServer(t)
	echoConn := socks5TestDial(t, socksAddr, echoAddr)
	_ = echoConn.SetDeadline(time.Now().Add(time.Second))
	echoPayload := []byte{1, 2, 3, 4, 5}
	_, _ = echoConn.Write(echoPayload)
	echoed := make([]byte, len(echoPayload))
	if _, err = io.ReadFull(echoConn, echoed); err != nil || string(echoed) != string(echoPayload) {
		t.Fatalf("non-HTTP SOCKS5 tunnel: response=%v err=%v", echoed, err)
	}
	_ = echoConn.Close()
	stopEcho()

	config.captureDomains = map[string]bool{"not-listed.example": true}
	transparentTransport := &nethttp.Transport{
		Proxy:             nethttp.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: upstreamRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	transparentClient := &nethttp.Client{Transport: transparentTransport, Timeout: 5 * time.Second}
	resp, err := transparentClient.Post(tlsServer.URL+"/unlisted-doh", "application/dns-message", strings.NewReader("doh-request"))
	if err != nil {
		t.Fatalf("unlisted HTTPS must stay transparent: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	transparentTransport.CloseIdleConnections()
	if err != nil || string(body) != "doh-response" {
		t.Fatalf("unlisted HTTPS response=%q err=%v", body, err)
	}
	httpExchangeSOCKS(t, socksAddr, tlsServer.URL+"/socks-unlisted-doh", upstreamRoots, "socks-doh-request", "socks-doh-response")

	want := []string{
		"plain-request", "plain-response", "secure-request", "secure-response",
		"ws-request", "ws-response", "wss-request", "wss-response",
		"socks-http-request", "socks-http-response", "socks-https-request", "socks-https-response",
		"socks-ws-request", "socks-ws-response", "socks-wss-request", "socks-wss-response",
	}
	logsDir := filepath.Join(config.CaptureDir, captureLogsDir)
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		t.Fatal(err)
	}
	var captured strings.Builder
	logCount := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".log" {
			continue
		}
		logCount++
		data, err := os.ReadFile(filepath.Join(logsDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		captured.Write(data)
	}
	if logCount != 8 {
		t.Errorf("capture log count=%d, want 8; non-HTTP SOCKS5 traffic must stay transparent", logCount)
	}
	for _, value := range want {
		if !strings.Contains(captured.String(), value) {
			t.Errorf("capture logs do not contain %q", value)
		}
	}
	if strings.Contains(captured.String(), "doh-request") {
		t.Error("unlisted HTTPS/DoH traffic was captured")
	}
}

func captureTestHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	if strings.Contains(r.URL.Path, "socket") {
		conn, rw, err := w.(nethttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = conn.Write([]byte(strings.Replace(line, "request", "response", 1)))
		return
	}
	body, _ := io.ReadAll(r.Body)
	_, _ = w.Write([]byte(strings.Replace(string(body), "request", "response", 1)))
}

func startCaptureTestProxy(t *testing.T) (*url.URL, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newHttpProxy(ln.Addr().String(), "")
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				newClientConn(conn, proxy).serve()
			}()
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}, func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	}
}

func startCaptureTestSOCKSProxy(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newSocksProxy(ln.Addr().String())
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				newClientConn(conn, proxy).serveSocks()
			}()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	}
}

func startCaptureTestEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
		_ = conn.Close()
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func webSocketExchange(t *testing.T, proxyAddr, target string, roots *x509.CertPool, request, response string) {
	t.Helper()
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := stdbufio.NewReader(conn)
	if targetURL.Scheme == "wss" {
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host, targetURL.Host)
		if header := readCaptureTestHeader(t, reader); !strings.Contains(header, " 200 ") {
			t.Fatalf("CONNECT failed: %s", header)
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: targetURL.Hostname(), RootCAs: roots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err = tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		conn = tlsConn
		reader = stdbufio.NewReader(tlsConn)
		target = targetURL.RequestURI()
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", target, targetURL.Host)
	if header := readCaptureTestHeader(t, reader); !strings.Contains(header, " 101 ") {
		t.Fatalf("websocket upgrade failed: %s", header)
	}
	if _, err = conn.Write([]byte(request + "\n")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response)+1)
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != response+"\n" {
		t.Fatalf("websocket response = %q, want %q", got, response)
	}
}

func socks5TestDial(t *testing.T, proxyAddr, targetAddr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte{socks5Version, 1, socks5AuthNone}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(conn, method[:]); err != nil || method != [2]byte{socks5Version, socks5AuthNone} {
		conn.Close()
		t.Fatalf("SOCKS5 negotiation: reply=%v err=%v", method, err)
	}
	host, portString, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	addrPort, err := buildSocks5AddrPort(host, uint16(port))
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	request := append([]byte{socks5Version, socks5CmdConnect, 0}, addrPort...)
	if _, err = conn.Write(request); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err = readSocks5ConnectReply(conn, targetAddr); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn
}

func httpExchangeSOCKS(t *testing.T, proxyAddr, target string, roots *x509.CertPool, request, response string) {
	t.Helper()
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	conn := socks5TestDial(t, proxyAddr, targetURL.Host)
	defer conn.Close()
	if targetURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: targetURL.Hostname(), RootCAs: roots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err = tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		conn = tlsConn
	}
	_, _ = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", targetURL.RequestURI(), targetURL.Host, len(request), request)
	resp, err := nethttp.ReadResponse(stdbufio.NewReader(conn), &nethttp.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != response {
		t.Fatalf("SOCKS5 HTTP response=%q err=%v", body, err)
	}
}

func webSocketExchangeSOCKS(t *testing.T, proxyAddr, target string, roots *x509.CertPool, request, response string) {
	t.Helper()
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	conn := socks5TestDial(t, proxyAddr, targetURL.Host)
	defer conn.Close()
	if targetURL.Scheme == "wss" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: targetURL.Hostname(), RootCAs: roots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err = tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		conn = tlsConn
	}
	reader := stdbufio.NewReader(conn)
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", targetURL.RequestURI(), targetURL.Host)
	if header := readCaptureTestHeader(t, reader); !strings.Contains(header, " 101 ") {
		t.Fatalf("SOCKS5 websocket upgrade failed: %s", header)
	}
	if _, err = conn.Write([]byte(request + "\n")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response)+1)
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != response+"\n" {
		t.Fatalf("SOCKS5 websocket response=%q, want %q", got, response)
	}
}

func readCaptureTestHeader(t *testing.T, r *stdbufio.Reader) string {
	t.Helper()
	var header strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		header.WriteString(line)
		if line == "\r\n" {
			return header.String()
		}
	}
}
