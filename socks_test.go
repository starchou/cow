package main

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestMergeListenProxies(t *testing.T) {
	proxies := []Proxy{
		newSocksProxy("127.0.0.1:7777"),
		newHttpProxy("0.0.0.0:7777", ""),
		newSocksProxy("127.0.0.1:8888"),
	}

	merged := mergeListenProxies(proxies)
	if len(merged) != 2 {
		t.Fatalf("want 2 listeners after merge, got %d", len(merged))
	}

	mp, ok := merged[0].(*mixedProxy)
	if !ok {
		t.Fatal("first listener should be mixedProxy")
	}
	if mp.addr != "0.0.0.0:7777" {
		t.Fatalf("mixed listener addr should prefer wildcard bind, got %s", mp.addr)
	}

	sp, ok := merged[1].(*socksProxy)
	if !ok {
		t.Fatal("second listener should remain socksProxy")
	}
	if sp.addr != "127.0.0.1:8888" {
		t.Fatalf("unexpected standalone socks5 addr %s", sp.addr)
	}
}

func TestMixedListenAddr(t *testing.T) {
	testData := []struct {
		httpAddr  string
		socksAddr string
		wantAddr  string
		wantOK    bool
	}{
		{"127.0.0.1:7777", "127.0.0.1:7777", "127.0.0.1:7777", true},
		{"localhost:7777", "127.0.0.1:7777", "127.0.0.1:7777", true},
		{"0.0.0.0:7777", "127.0.0.1:7777", "0.0.0.0:7777", true},
		{"127.0.0.1:7777", "127.0.0.1:8888", "", false},
		{"127.0.0.1:7777", "192.168.1.1:7777", "", false},
	}

	for _, td := range testData {
		addr, ok := mixedListenAddr(td.httpAddr, td.socksAddr)
		if ok != td.wantOK {
			t.Fatalf("%s + %s want ok=%v, got %v", td.httpAddr, td.socksAddr, td.wantOK, ok)
		}
		if addr != td.wantAddr {
			t.Fatalf("%s + %s want addr=%s, got %s", td.httpAddr, td.socksAddr, td.wantAddr, addr)
		}
	}
}

func TestEstablishParentConnectForSocks(t *testing.T) {
	serverSide, parentSide := net.Pipe()
	defer serverSide.Close()
	defer parentSide.Close()

	parent := &httpParent{
		server:     "127.0.0.1:8080",
		authHeader: []byte("proxy-authorization: Basic dXNlcjpwYXNz\r\n"),
	}
	sv := newServerConn(httpConn{serverSide, parent}, "www.cloudflare.com:443", alwaysDirectVisitCnt)
	r := &Request{
		Method:    "CONNECT",
		isConnect: true,
		URL:       &URL{HostPort: "www.cloudflare.com:443"},
	}

	reqCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		defer close(reqCh)
		defer close(errCh)
		buf := make([]byte, 4096)
		n, err := parentSide.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		reqCh <- string(buf[:n])
		_, err = io.WriteString(parentSide, "HTTP/1.1 200 Tunnel established\r\n\r\n")
		errCh <- err
	}()

	if err := sv.establishParentConnect(r, nil); err != nil {
		t.Fatalf("establishParentConnect returned error: %v", err)
	}

	req := <-reqCh
	if !strings.Contains(req, "CONNECT www.cloudflare.com:443 HTTP/1.1\r\n") {
		t.Fatalf("parent request line missing or malformed: %q", req)
	}
	if !strings.Contains(req, "Host: www.cloudflare.com:443\r\n") {
		t.Fatalf("parent host header missing: %q", req)
	}
	if !strings.Contains(req, "proxy-authorization: Basic dXNlcjpwYXNz\r\n") {
		t.Fatalf("parent auth header missing: %q", req)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("parent side write error: %v", err)
	}
}
