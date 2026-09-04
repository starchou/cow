package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureGeneratesCAAndWritesTraffic(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	config.Capture = true
	config.CaptureDir = t.TempDir()
	config.CaptureDomainFile = filepath.Join(config.CaptureDir, "domain.list")
	if err := os.WriteFile(config.CaptureDomainFile, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initCapture(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.CaptureDir, captureCACertName)); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(config.CaptureDir, captureLogsDir)); err != nil || !info.IsDir() {
		t.Fatalf("capture logs directory was not created: %v", err)
	}
	keyInfo, err := os.Stat(filepath.Join(config.CaptureDir, captureCAKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("CA key permissions are too broad: %o", keyInfo.Mode().Perm())
	}

	leaf, err := captureCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(captureCA.cert)
	if _, err = leafCert.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Fatalf("generated leaf does not verify: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	serverTLS := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})
	clientTLS := tls.Client(clientConn, &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- serverTLS.Handshake() }()
	if err = clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake with generated leaf failed: %v", err)
	}
	if err = <-handshakeDone; err != nil {
		t.Fatalf("server handshake with generated leaf failed: %v", err)
	}
	_ = clientConn.Close()
	_ = serverConn.Close()

	var r Request
	r.reset()
	defer r.releaseBuf()
	r.Method = "POST"
	r.URL = &URL{HostPort: "example.com:80", Host: "example.com", Port: "80", Domain: "example.com", Path: "/api/items.json"}
	r.genRequestLine()
	r.raw.WriteString("Host: example.com\r\nContent-Length: 7\r\n\r\n")
	capture := startTrafficCapture(&r, "http")
	if capture == nil {
		t.Fatal("capture was not created")
	}
	w := capture.writer("client -> server body")
	_, _ = w.Write([]byte("pay"))
	_, _ = w.Write([]byte("load"))
	capture.close()

	logs, err := filepath.Glob(filepath.Join(config.CaptureDir, captureLogsDir, "example.com_items.json_*.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected one timestamped log, got %v, %v", logs, err)
	}
	content, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "POST /api/items.json HTTP/1.1") || !strings.Contains(string(content), "payload") {
		t.Fatalf("capture is missing request content:\n%s", content)
	}
}

func TestCaptureDomainWhitelist(t *testing.T) {
	oldDomains := config.captureDomains
	defer func() { config.captureDomains = oldDomains }()

	file := filepath.Join(t.TempDir(), "domain.list")
	if err := os.WriteFile(file, []byte("# capture targets\nExample.COM\n*.service.local\n\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	domains, err := loadCaptureDomainFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 {
		t.Fatalf("loaded %d capture domains, want 3", len(domains))
	}
	config.captureDomains = domains
	tests := map[string]bool{
		"example.com":          true,
		"api.example.com":      true,
		"SERVICE.LOCAL.":       true,
		"api.service.local":    true,
		"192.0.2.1":            true,
		"notexample.com":       false,
		"unlisted.example.org": false,
		"sub.192.0.2.1":        false,
	}
	for host, want := range tests {
		if got := captureDomainAllowed(host); got != want {
			t.Errorf("captureDomainAllowed(%q)=%v, want %v", host, got, want)
		}
	}
	config.captureDomains = nil
	if captureDomainAllowed("example.com") {
		t.Fatal("empty whitelist must capture nothing")
	}
	config.captureDomains = map[string]bool{"*": true}
	if !captureDomainAllowed("anything.example") {
		t.Fatal("wildcard whitelist must capture every domain")
	}
}
