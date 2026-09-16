package main

import (
	stdbufio "bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Laisky/cow/plugins/masterrummy"
)

func masterrummyTestEncrypt(text string) string {
	key := []byte("5059b898a9420817732621e597de65a7")
	iv := []byte("1102736404060702")
	data := []byte(text)
	n := aes.BlockSize - len(data)%aes.BlockSize
	data = append(data, bytes.Repeat([]byte{byte(n)}, n)...)
	block, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	return base64.StdEncoding.EncodeToString(data)
}

func masterrummyTestRequest(channel string) string {
	plain := "action=Hall.get&ver=2.2.9&sid=0&param=" + url.QueryEscape(`{"channel_id":`+channel+`,"msg":"你好 + test"}`)
	return "/i.php?" + url.QueryEscape(masterrummyTestEncrypt(plain))
}

func TestMasterrummyDecode(t *testing.T) {
	request := masterrummyTestRequest("2000572")
	response := "aes#" + masterrummyTestEncrypt(`{"action":"Hall.get","data":{"uid":9007199254740993},"ret":0}`)
	decoded, err := masterrummy.Decode(request, nil, []byte(response))
	if err != nil || decoded.Action != "Hall.get" || decoded.UID != "9007199254740993" ||
		!strings.Contains(string(decoded.RequestJSON), "你好 + test") {
		t.Fatalf("valid protocol round-trip failed: %v", err)
	}
	postDecoded, err := masterrummy.Decode("/i.php", []byte(strings.SplitN(request, "?", 2)[1]), []byte(response))
	if err != nil || postDecoded.RequestPlaintext != decoded.RequestPlaintext {
		t.Fatalf("POST encrypted-body decoding failed: %v", err)
	}
	for _, tc := range []struct{ request, response string }{
		{masterrummyTestRequest("2000611"), response},
		{request, `{"uid":123}`},
		{request, "aes#AAAA"},
		{request, "aes#" + masterrummyTestEncrypt("not json")},
		{request, "aes#" + masterrummyTestEncrypt(`{"action":"Other"}`)},
		{"/i.php?invalid", response},
		{"/other.php?invalid", response},
	} {
		if _, err := masterrummy.Decode(tc.request, nil, []byte(tc.response)); err == nil {
			t.Fatal("invalid/wrong-package/plaintext exchange was accepted")
		}
	}
}

func TestPluginConfiguration(t *testing.T) {
	oldConfig, oldPlugin := config, httpPlugin
	defer func() { config, httpPlugin = oldConfig, oldPlugin }()
	initConfig(filepath.Join(t.TempDir(), "rc"))
	if config.Plugin != "" {
		t.Fatal("plugins must be opt-in")
	}
	parser := configParser{}
	parser.ParsePlugin("masterrummy")
	parser.ParsePluginDBFile("~/.cow/masterrummy.sqlite3")
	if config.PluginDBFile != expandTilde("~/.cow/masterrummy.sqlite3") {
		t.Fatal("plugin database path was not expanded")
	}
	parser.ParsePlugin("missing-module")
	if err := initHTTPPlugin(); err == nil {
		t.Fatal("unknown module must produce a startup error")
	}
}

func TestPluginAdmissionDoesNotBlock(t *testing.T) {
	p := &httpPluginWriter{jobs: make(chan *pluginExchange, 1), slots: make(chan struct{}, 1)}
	var r Request
	r.reset()
	defer r.releaseBuf()
	r.URL = &URL{Host: "example.test", Path: "/i.php?test"}
	first := p.begin(&r)
	if first == nil {
		t.Fatal("first request was rejected")
	}
	done := make(chan *pluginExchange, 1)
	go func() { done <- p.begin(&r) }()
	select {
	case got := <-done:
		if got != nil || p.dropped.Load() != 1 {
			t.Fatal("full admission buffer must drop the request")
		}
	case <-time.After(time.Second):
		t.Fatal("plugin blocked the proxy waiting for capacity")
	}
	first.discard()
	e := p.begin(&r)
	_, _ = e.responseBody.Write(make([]byte, pluginBodyLimit+1))
	e.submit()
	if len(p.slots) != 0 || len(p.jobs) != 0 || p.dropped.Load() != 2 {
		t.Fatal("oversize exchange must be discarded and release its slot")
	}
}

func TestPluginHTTPAsyncSQLite(t *testing.T) {
	oldConfig, oldPlugin, oldParent, oldSite := config, httpPlugin, parentProxy, siteStat
	oldTLSConfig := newCaptureUpstreamTLSConfig
	defer func() {
		config, httpPlugin, parentProxy, siteStat = oldConfig, oldPlugin, oldParent, oldSite
		newCaptureUpstreamTLSConfig = oldTLSConfig
	}()
	dir := t.TempDir()
	initConfig(filepath.Join(dir, "rc"))
	config.Plugin = "masterrummy"
	config.PluginDBFile = filepath.Join(dir, "db", "records.sqlite3")
	config.Capture = true
	config.CaptureDomainFile = filepath.Join(dir, "domain.list")
	if err := os.WriteFile(config.CaptureDomainFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initCapture(); err != nil {
		t.Fatal(err)
	}
	parentProxy, siteStat = &backupParentPool{}, newSiteStat()
	if err := initHTTPPlugin(); err != nil {
		t.Fatal(err)
	}
	p := httpPlugin
	defer p.close()
	response := "aes#" + masterrummyTestEncrypt(`{"action":"Hall.get","data":{"uid":"12345"},"ret":0}`)
	handler := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body := response
		if r.Header.Get("X-Test-Invalid") != "" {
			body = "aes#invalid"
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		w.(nethttp.Flusher).Flush() // force chunked response
		z := gzip.NewWriter(w)
		_, _ = z.Write([]byte(body))
		_ = z.Close()
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	tlsServer := httptest.NewTLSServer(handler)
	defer tlsServer.Close()
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(tlsServer.Certificate())
	newCaptureUpstreamTLSConfig = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, RootCAs: upstreamRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(captureCA.cert)
	proxyURL, stopProxy := startCaptureTestProxy(t)
	defer stopProxy()
	socksAddr, stopSocks := startCaptureTestSOCKSProxy(t)
	defer stopSocks()
	transport := &nethttp.Transport{Proxy: nethttp.ProxyURL(proxyURL), DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig: &tls.Config{RootCAs: clientRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &nethttp.Client{Transport: transport, Timeout: 2 * time.Second}
	socksTransport := transport.Clone()
	socksTransport.Proxy = nethttp.ProxyURL(&url.URL{Scheme: "socks5", Host: socksAddr})
	defer socksTransport.CloseIdleConnections()
	socksClient := &nethttp.Client{Transport: socksTransport, Timeout: 2 * time.Second}
	// Hold a SQLite writer lock throughout both requests; forwarding must finish
	// before the lock is released, even while the worker waits in busy_timeout.
	blocker, err := sql.Open("sqlite", config.PluginDBFile)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err := blocker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer blocker.Exec("ROLLBACK")
	before := time.Now()
	for _, tc := range []struct {
		client  *nethttp.Client
		origin  string
		invalid bool
	}{
		{client, server.URL, false}, {client, server.URL, true}, {client, tlsServer.URL, false},
		{socksClient, server.URL, false}, {socksClient, tlsServer.URL, false},
	} {
		req, _ := nethttp.NewRequest("GET", tc.origin+masterrummyTestRequest("2000572"), nil)
		if tc.invalid {
			req.Header.Set("X-Test-Invalid", "1")
		}
		res, err := tc.client.Do(req)
		if err != nil {
			t.Fatalf("proxy stalled with a locked database: %v", err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || len(body) == 0 {
			t.Fatal("proxy failed to forward the response")
		}
	}
	if _, err := blocker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	p.close() // drain the queue and release SQLite
	if p.written.Load() != 4 || p.skipped.Load() != 1 || len(p.slots) != 0 {
		t.Fatalf("unexpected plugin counts: stored=%d skipped=%d slots=%d", p.written.Load(), p.skipped.Load(), len(p.slots))
	}
	var action, uid, pkg, domain, parsed, rawHeader string
	var stamp int64
	err = blocker.QueryRow(`SELECT action,uid,package_name,domain,parsed_response,request_time_ns,CAST(request_headers AS TEXT) FROM plugin_http_records`).Scan(&action, &uid, &pkg, &domain, &parsed, &stamp, &rawHeader)
	if err != nil || action != "Hall.get" || uid != "12345" || pkg != masterrummy.PackageName || domain != "127.0.0.1" ||
		!strings.Contains(parsed, "12345") || !strings.Contains(rawHeader, "GET /i.php?") || stamp < before.UnixNano() || stamp > time.Now().UnixNano() {
		t.Fatalf("stored row failed validation: %v", err)
	}
	var indexes int
	if err := blocker.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='plugin_http_records'`).Scan(&indexes); err != nil || indexes != 4 {
		t.Fatalf("query indexes missing: %d, %v", indexes, err)
	}
}

// Optional real fixture validation. Raw personal data stays in the user's
// supplied directory; only aggregate counts are printed and the DB is temporary.
func TestPluginLocalA572Logs(t *testing.T) {
	dir := os.Getenv("COW_A572_LOG_DIR")
	if dir == "" {
		t.Skip("set COW_A572_LOG_DIR to validate existing a572 capture logs offline")
	}
	files, err := filepath.Glob(filepath.Join(dir, "i.php_*.log"))
	if err != nil || len(files) == 0 {
		t.Fatal("no a572 fixtures found")
	}
	p, err := newHTTPPluginWriter(filepath.Join(t.TempDir(), "fixtures.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		section := func(label string) string {
			parts := strings.SplitN(string(raw), label+" =====", 2)
			if len(parts) != 2 {
				t.Fatalf("missing section %s in %s", label, filepath.Base(file))
			}
			return strings.TrimSpace(strings.SplitN(parts[1], "\n=====", 2)[0])
		}
		rqHeader, rpHeader := section("client -> server request"), section("server -> client response")
		rq, err := nethttp.ReadRequest(stdbufio.NewReader(strings.NewReader(rqHeader + "\r\n\r\n")))
		if err != nil {
			t.Fatal(err)
		}
		rp, err := nethttp.ReadResponse(stdbufio.NewReader(strings.NewReader(rpHeader+"\r\n\r\n")), rq)
		if err != nil {
			t.Fatal(err)
		}
		body := section("server -> client body")
		body = strings.TrimSpace(strings.TrimPrefix(body, "encoding: base64"))
		wire, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
		if err != nil {
			t.Fatal(err)
		}
		domain, _, _ := net.SplitHostPort(rq.Host)
		if domain == "" {
			domain = rq.Host
		}
		e := &pluginExchange{domain: domain, method: rq.Method, target: rq.RequestURI,
			requestedAt: time.Now(), status: rp.StatusCode, requestHeaders: []byte(rqHeader), responseHeaders: []byte(rpHeader),
			responseMeta: Header{Chunking: len(rp.TransferEncoding) > 0, ContentEncoding: rp.Header.Get("Content-Encoding")},
			responseBody: pluginBody{data: wire}}
		p.store(e)
	}
	if p.written.Load() != uint64(len(files)) {
		t.Fatalf("real fixtures stored=%d skipped=%d db_errors=%d expected=%d", p.written.Load(), p.skipped.Load(), p.failed.Load(), len(files))
	}
	t.Logf("validated %d real a572 request/response pairs into SQLite", len(files))
}

func TestPluginTransportBody(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	z.Write([]byte("encrypted response"))
	z.Close()
	wire := []byte(fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", compressed.Len(), compressed.Bytes()))
	body, err := pluginEntityBody(wire, Header{Chunking: true, ContentEncoding: "gzip"})
	if err != nil || string(body) != "encrypted response" {
		t.Fatalf("chunked gzip decoding: %v", err)
	}
}
