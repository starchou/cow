package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Laisky/cow/plugins/masterrummy"
	_ "modernc.org/sqlite"
)

const pluginBodyLimit = 1 << 20 // 1 MiB per wire/decoded body
const pluginPendingLimit = 64   // includes in-flight requests, queued jobs and the DB writer

const pluginSchema = `
CREATE TABLE IF NOT EXISTS plugin_http_records (
 id INTEGER PRIMARY KEY,
 plugin TEXT NOT NULL,
 package_name TEXT NOT NULL,
 domain TEXT NOT NULL,
 method TEXT NOT NULL,
 url TEXT NOT NULL,
 request_time_ns INTEGER NOT NULL,
 request_time TEXT NOT NULL,
 status_code INTEGER NOT NULL,
 request_headers BLOB NOT NULL,
 request_body BLOB NOT NULL,
 response_headers BLOB NOT NULL,
 response_body BLOB NOT NULL,
 request_plaintext TEXT NOT NULL,
 response_plaintext TEXT NOT NULL,
 parsed_request TEXT NOT NULL,
 parsed_response TEXT NOT NULL,
 action TEXT NOT NULL,
 uid TEXT
);
CREATE INDEX IF NOT EXISTS plugin_http_action_time ON plugin_http_records(action, request_time_ns DESC);
CREATE INDEX IF NOT EXISTS plugin_http_uid_time ON plugin_http_records(uid, request_time_ns DESC);
CREATE INDEX IF NOT EXISTS plugin_http_domain_time ON plugin_http_records(domain, request_time_ns DESC);
CREATE INDEX IF NOT EXISTS plugin_http_time ON plugin_http_records(request_time_ns DESC);
`

var httpPlugin *httpPluginWriter

type httpPluginWriter struct {
	db      *sql.DB
	jobs    chan *pluginExchange
	slots   chan struct{}
	done    chan struct{}
	mu      sync.RWMutex // protects closing jobs against submit/begin; never held during I/O
	closed  bool
	written atomic.Uint64
	skipped atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
}

func initHTTPPlugin() error {
	if config.Plugin == "" {
		return nil
	}
	if config.Plugin != "masterrummy" {
		return fmt.Errorf("unknown plugin %q (supported: masterrummy)", config.Plugin)
	}
	var err error
	httpPlugin, err = newHTTPPluginWriter(config.PluginDBFile)
	if err == nil {
		info.Printf("HTTP plugin masterrummy enabled; SQLite: %s\n", config.PluginDBFile)
	}
	return err
}

func newHTTPPluginWriter(file string) (*httpPluginWriter, error) {
	if file == "" {
		return nil, errors.New("pluginDBFile is empty")
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", file)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA busy_timeout=3000; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;" + pluginSchema); err != nil {
		db.Close()
		return nil, err
	}
	p := &httpPluginWriter{db: db, jobs: make(chan *pluginExchange, pluginPendingLimit),
		slots: make(chan struct{}, pluginPendingLimit), done: make(chan struct{})}
	go p.run()
	return p, nil
}

type pluginBody struct {
	data     []byte
	tooLarge bool
}

func (b *pluginBody) Write(p []byte) (int, error) {
	if !b.tooLarge {
		if len(b.data)+len(p) > pluginBodyLimit {
			b.data, b.tooLarge = nil, true
		} else {
			b.data = append(b.data, p...)
		}
	}
	return len(p), nil
}

type pluginExchange struct {
	owner                           *httpPluginWriter
	released                        bool // owned by the proxy until submit, then by the worker
	domain, method, target          string
	requestedAt                     time.Time
	status                          int
	requestHeaders, responseHeaders []byte
	requestMeta, responseMeta       Header
	requestBody, responseBody       pluginBody
}

func (p *httpPluginWriter) begin(r *Request) *pluginExchange {
	if p == nil || r.isConnect || r.Upgrade != "" || strings.SplitN(r.URL.Path, "?", 2)[0] != "/i.php" {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil
	}
	if len(r.rawRequest()) > pluginBodyLimit {
		p.dropped.Add(1)
		return nil
	}
	select {
	case p.slots <- struct{}{}:
	default:
		p.dropped.Add(1)
		return nil
	}
	return &pluginExchange{owner: p, domain: r.URL.Host, method: r.Method, target: r.URL.Path,
		requestedAt: r.startedAt, requestHeaders: append([]byte(nil), r.rawRequest()...), requestMeta: r.Header}
}

func (e *pluginExchange) discard() {
	if e != nil && !e.released {
		e.released = true
		<-e.owner.slots
	}
}

func (e *pluginExchange) submit() {
	if e == nil || e.released {
		return
	}
	p := e.owner
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || e.requestBody.tooLarge || e.responseBody.tooLarge {
		p.dropped.Add(1)
		e.discard()
		return
	}
	select {
	case p.jobs <- e:
	default:
		p.dropped.Add(1)
		e.discard()
	}
}

func (p *httpPluginWriter) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.jobs)
	}
	p.mu.Unlock()
	<-p.done
}

func (p *httpPluginWriter) run() {
	defer close(p.done)
	defer p.db.Close()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var reported uint64
	for {
		select {
		case e, ok := <-p.jobs:
			if !ok {
				info.Printf("plugin masterrummy stopped: stored=%d skipped=%d dropped=%d db_errors=%d\n",
					p.written.Load(), p.skipped.Load(), p.dropped.Load(), p.failed.Load())
				return
			}
			p.store(e)
			e.discard()
		case <-ticker.C:
			if n := p.dropped.Load(); n != reported {
				errl.Printf("plugin masterrummy dropped %d records (capacity, body limit or shutdown)\n", n)
				reported = n
			}
		}
	}
}

func (p *httpPluginWriter) store(e *pluginExchange) {
	request, err := pluginEntityBody(e.requestBody.data, e.requestMeta)
	if err != nil {
		p.skipped.Add(1)
		return
	}
	response, err := pluginEntityBody(e.responseBody.data, e.responseMeta)
	if err != nil {
		p.skipped.Add(1)
		return
	}
	decoded, err := masterrummy.Decode(e.target, request, response)
	if err != nil {
		p.skipped.Add(1)
		return
	}
	var uid interface{}
	if decoded.UID != "" {
		uid = decoded.UID
	}
	_, err = p.db.Exec(`INSERT INTO plugin_http_records
 (plugin,package_name,domain,method,url,request_time_ns,request_time,status_code,
 request_headers,request_body,response_headers,response_body,request_plaintext,response_plaintext,
 parsed_request,parsed_response,action,uid) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"masterrummy", masterrummy.PackageName, e.domain, e.method, e.target, e.requestedAt.UnixNano(),
		e.requestedAt.Format(time.RFC3339Nano), e.status, e.requestHeaders, nonNilBytes(e.requestBody.data),
		e.responseHeaders, nonNilBytes(e.responseBody.data), decoded.RequestPlaintext, decoded.ResponsePlaintext,
		string(decoded.RequestJSON), string(decoded.ResponseJSON), decoded.Action, uid)
	if err != nil {
		p.failed.Add(1)
		errl.Printf("plugin masterrummy database write failed: %v\n", err)
		return
	}
	p.written.Add(1)
}

func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func pluginEntityBody(raw []byte, h Header) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(raw)
	if h.Chunking {
		reader = httputil.NewChunkedReader(reader)
	}
	body, err := readPluginBody(reader)
	if err != nil {
		return nil, err
	}
	encodings := strings.Split(strings.ToLower(h.ContentEncoding), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		var decoder io.ReadCloser
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			decoder, err = gzip.NewReader(bytes.NewReader(body))
		case "deflate":
			decoder, err = zlib.NewReader(bytes.NewReader(body))
			if err != nil {
				decoder, err = flate.NewReader(bytes.NewReader(body)), nil
			}
		default:
			return nil, errors.New("unsupported plugin content encoding")
		}
		if err != nil {
			return nil, err
		}
		body, err = readPluginBody(decoder)
		decoder.Close()
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

func readPluginBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, pluginBodyLimit+1))
	if len(data) > pluginBodyLimit {
		return nil, errors.New("plugin body too large")
	}
	return data, err
}
