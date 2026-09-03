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
		TLSClientConfig:   &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12},
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

	want := []string{"plain-request", "plain-response", "secure-request", "secure-response", "ws-request", "ws-response", "wss-request", "wss-response"}
	entries, err := os.ReadDir(config.CaptureDir)
	if err != nil {
		t.Fatal(err)
	}
	var captured strings.Builder
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".log" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(config.CaptureDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		captured.Write(data)
	}
	for _, value := range want {
		if !strings.Contains(captured.String(), value) {
			t.Errorf("capture logs do not contain %q", value)
		}
	}
}

func captureTestHandler(w nethttp.ResponseWriter, r *nethttp.Request) {
	secure := strings.Contains(r.URL.Path, "secure")
	if strings.Contains(r.URL.Path, "socket") {
		conn, rw, err := w.(nethttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		var buf []byte
		if secure {
			buf = make([]byte, len("wss-request"))
		} else {
			buf = make([]byte, len("ws-request"))
		}
		_, _ = io.ReadFull(rw, buf)
		if secure {
			_, _ = conn.Write([]byte("wss-response"))
		} else {
			_, _ = conn.Write([]byte("ws-response"))
		}
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
	if _, err = conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != response {
		t.Fatalf("websocket response = %q, want %q", got, response)
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
