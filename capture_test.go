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
	if err := initCapture(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.CaptureDir, captureCACertName)); err != nil {
		t.Fatal(err)
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

	logs, err := filepath.Glob(filepath.Join(config.CaptureDir, "example.com_items.json_*.log"))
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
