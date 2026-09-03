package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cyfdecyf/bufio"
)

const (
	captureCACertName = "cow-ca.crt"
	captureCAKeyName  = "cow-ca.key"
	captureCAURLPath  = "/cow-ca.crt"
	captureLogsDir    = "logs"
)

var captureCA = struct {
	sync.Mutex
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	leaf    map[string]tls.Certificate
}{leaf: make(map[string]tls.Certificate)}

var newCaptureUpstreamTLSConfig = func(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

func initCapture() error {
	if !config.Capture {
		return nil
	}
	if config.CaptureDir == "" {
		return errors.New("captureDir is empty")
	}
	dir, err := filepath.Abs(config.CaptureDir)
	if err != nil {
		return err
	}
	config.CaptureDir = dir
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(dir, captureLogsDir), 0700); err != nil {
		return err
	}

	certPath := filepath.Join(dir, captureCACertName)
	keyPath := filepath.Join(dir, captureCAKeyName)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		certPEM, keyPEM, err = generateCaptureCA()
		if err != nil {
			return err
		}
		if err = os.WriteFile(certPath, certPEM, 0644); err != nil {
			return err
		}
		if err = os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
	} else if certErr != nil || keyErr != nil {
		return fmt.Errorf("both %s and %s must exist, or neither", certPath, keyPath)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("load capture CA: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse capture CA: %w", err)
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || !cert.IsCA {
		return errors.New("capture CA is not a signing certificate")
	}

	captureCA.Lock()
	captureCA.cert = cert
	captureCA.key = key
	captureCA.certPEM = certPEM
	captureCA.leaf = make(map[string]tls.Certificate)
	captureCA.Unlock()
	info.Printf("traffic capture enabled: %s; CA certificate: %s\n", dir, certPath)
	return nil
}

func generateCaptureCA() ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "COW Traffic Capture CA", Organization: []string{"COW"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func captureCertificate(host string) (tls.Certificate, error) {
	captureCA.Lock()
	defer captureCA.Unlock()
	if cert, ok := captureCA.leaf[host]; ok {
		return cert, nil
	}
	if captureCA.cert == nil || captureCA.key == nil {
		return tls.Certificate{}, errors.New("capture CA is not initialized")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	notAfter := now.AddDate(0, 1, 0)
	if notAfter.After(captureCA.cert.NotAfter) {
		notAfter = captureCA.cert.NotAfter
	}
	tpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, captureCA.cert, &key.PublicKey, captureCA.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der, captureCA.cert.Raw}, PrivateKey: key, Leaf: leaf}
	captureCA.leaf[host] = cert
	return cert, nil
}

type trafficCapture struct {
	sync.Mutex
	file *os.File
}

func startTrafficCapture(r *Request, protocol string) *trafficCapture {
	if !config.Capture {
		return nil
	}
	base := path.Base(strings.SplitN(r.URL.Path, "?", 2)[0])
	if base == "." || base == "/" || base == "" {
		base = "root"
	}
	name := cleanCaptureName(r.URL.Host + "_" + base)
	name += "_" + time.Now().Format("20060102_150405.000000000") + ".log"
	f, err := os.OpenFile(filepath.Join(config.CaptureDir, captureLogsDir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		errl.Printf("create traffic capture: %v\n", err)
		return nil
	}
	c := &trafficCapture{file: f}
	c.writeSection("metadata", []byte(fmt.Sprintf("time: %s\nprotocol: %s\ntarget: %s\n", time.Now().Format(time.RFC3339Nano), protocol, r.URL)))
	c.writeSection("client -> server request", r.rawRequest())
	return c
}

func cleanCaptureName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 100 {
			break
		}
	}
	if b.Len() == 0 {
		return "traffic"
	}
	return b.String()
}

func (c *trafficCapture) writeSection(label string, p []byte) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	if c.file == nil {
		return
	}
	if _, err := fmt.Fprintf(c.file, "\n===== %s %s =====\n", time.Now().Format(time.RFC3339Nano), label); err == nil {
		_, err = c.file.Write(p)
		if len(p) > 0 && p[len(p)-1] != '\n' {
			_, _ = c.file.Write([]byte("\n"))
		}
	}
}

func (c *trafficCapture) writer(label string) io.Writer {
	return &capturePayloadWriter{capture: c, label: label}
}

func (c *trafficCapture) chunkWriter(label string) io.Writer {
	return captureChunkWriter{capture: c, label: label}
}

func (c *trafficCapture) close() {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	if c.file != nil {
		_ = c.file.Close()
		c.file = nil
	}
}

type capturePayloadWriter struct {
	capture *trafficCapture
	label   string
	started bool
}

type captureChunkWriter struct {
	capture *trafficCapture
	label   string
}

func (w captureChunkWriter) Write(p []byte) (int, error) {
	w.capture.writeSection(w.label, p)
	return len(p), nil
}

func (w *capturePayloadWriter) Write(p []byte) (int, error) {
	w.capture.Lock()
	if w.capture.file != nil {
		if !w.started {
			_, _ = fmt.Fprintf(w.capture.file, "\n===== %s %s =====\n", time.Now().Format(time.RFC3339Nano), w.label)
			w.started = true
		}
		_, _ = w.capture.file.Write(p)
	}
	w.capture.Unlock()
	return len(p), nil
}

type bufferedNetConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedNetConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (sv *serverConn) doCaptureConnect(r *Request, c *clientConn) error {
	if err := sv.establishParentConnect(r, c); err != nil {
		sv.Close()
		return err
	}
	if !r.isRetry() {
		if _, err := c.Write(connEstablished); err != nil {
			sv.Close()
			return err
		}
	}

	setConnReadTimeout(c.Conn, config.DialTimeout, "detect TLS capture")
	first, err := c.bufRd.Peek(1)
	isHTTP := err == nil && first[0] == 0x16 && captureTLSLooksHTTP(c.bufRd, r.URL.Port)
	unsetConnReadTimeout(c.Conn, "detect TLS capture")
	if err != nil {
		sv.Close()
		return err
	}
	if !isHTTP {
		return sv.tunnel(r, c)
	}
	return sv.captureTLS(c, r.URL)
}

func (sv *serverConn) doCaptureSocks(r *Request, c *clientConn) error {
	setConnReadTimeout(c.Conn, config.DialTimeout, "detect SOCKS5 capture protocol")
	first, err := c.bufRd.Peek(1)
	if err != nil {
		unsetConnReadTimeout(c.Conn, "detect SOCKS5 capture protocol")
		return sv.tunnel(r, c)
	}
	if first[0] == 0x16 && captureTLSLooksHTTP(c.bufRd, r.URL.Port) {
		unsetConnReadTimeout(c.Conn, "detect SOCKS5 capture protocol")
		return sv.captureTLS(c, r.URL)
	}
	unsetConnReadTimeout(c.Conn, "detect SOCKS5 capture protocol")
	if first[0] == 0x16 || !captureLooksLikeHTTP(c.bufRd, first[0]) {
		return sv.tunnel(r, c)
	}
	sv.tunneled = true
	sv.updateVisit()
	defer sv.Close()
	return sv.serveCapturedHTTP(c, r.URL, false)
}

func captureLooksLikeHTTP(reader *bufio.Reader, first byte) bool {
	switch first {
	case 'G', 'P', 'H', 'D', 'O', 'T', 'C':
	default:
		return false
	}
	prefix, err := reader.Peek(4)
	if err != nil {
		return false
	}
	switch string(prefix) {
	case "GET ", "PUT ":
		return true
	case "POST", "PATC", "HEAD", "DELE", "OPTI", "TRAC", "CONN":
	default:
		return false
	}
	method, err := reader.PeekSlice(' ')
	return err == nil && isCaptureHTTPMethod(string(method[:len(method)-1]))
}

func isCaptureHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}

func captureTLSLooksHTTP(reader *bufio.Reader, port string) bool {
	header, err := reader.Peek(5)
	if err != nil || header[0] != 0x16 {
		return false
	}
	record, err := reader.Peek(5 + int(binary.BigEndian.Uint16(header[3:5])))
	if err == nil && clientHelloHasHTTPALPN(record[5:]) {
		return true
	}
	return port == "443" || port == "8443"
}

func clientHelloHasHTTPALPN(hello []byte) bool {
	if len(hello) < 39 || hello[0] != 1 {
		return false
	}
	handshakeLen := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
	if handshakeLen+4 > len(hello) {
		return false
	}
	pos := 38
	if pos+1 > len(hello) {
		return false
	}
	pos += 1 + int(hello[pos])
	if pos+2 > len(hello) {
		return false
	}
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	if pos+1 > len(hello) {
		return false
	}
	pos += 1 + int(hello[pos])
	if pos+2 > len(hello) {
		return false
	}
	extensionsEnd := pos + 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	pos += 2
	if extensionsEnd > len(hello) {
		return false
	}
	for pos+4 <= extensionsEnd {
		typeID := binary.BigEndian.Uint16(hello[pos : pos+2])
		size := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4
		if pos+size > extensionsEnd {
			return false
		}
		if typeID == 16 && size >= 2 {
			protocols := hello[pos+2 : pos+size]
			for len(protocols) > 0 {
				n := int(protocols[0])
				if n+1 > len(protocols) {
					return false
				}
				protocol := string(protocols[1 : n+1])
				if protocol == "h2" || protocol == "http/1.1" {
					return true
				}
				protocols = protocols[n+1:]
			}
		}
		pos += size
	}
	return false
}

func (sv *serverConn) captureTLS(c *clientConn, target *URL) error {
	sv.releaseBuf()
	serverTLS := tls.Client(sv.Conn, newCaptureUpstreamTLSConfig(target.Host))
	_ = serverTLS.SetDeadline(time.Now().Add(config.DialTimeout))
	if err := serverTLS.Handshake(); err != nil {
		sv.Close()
		if sv.maybeFake() && maybeBlocked(err) {
			siteStat.TempBlocked(target)
			return RetryError{err}
		}
		return fmt.Errorf("server TLS handshake: %w", err)
	}
	_ = serverTLS.SetDeadline(time.Time{})
	sv.updateVisit()
	sv.Conn = serverTLS
	defer sv.Close()

	cert, err := captureCertificate(target.Host)
	if err != nil {
		return err
	}
	encryptedReader, encryptedBuf := c.bufRd, c.buf
	c.bufRd, c.buf = nil, nil
	defer httpBuf.Put(encryptedBuf)
	clientTLS := tls.Server(&bufferedNetConn{Conn: c.Conn, reader: encryptedReader}, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	_ = clientTLS.SetDeadline(time.Now().Add(config.DialTimeout))
	if err = clientTLS.Handshake(); err != nil {
		return fmt.Errorf("client TLS handshake: %w", err)
	}
	_ = clientTLS.SetDeadline(time.Time{})
	c.Conn = clientTLS
	c.buf = httpBuf.Get()
	c.bufRd = bufio.NewReaderFromBuf(clientTLS, c.buf)

	err = sv.serveCapturedHTTP(c, target, true)
	if isErrRetry(err) {
		return fmt.Errorf("captured TLS connection cannot retry: %w", err)
	}
	return err
}

func (sv *serverConn) serveCapturedHTTP(c *clientConn, target *URL, secure bool) error {
	for {
		var r Request
		var rp Response
		if err := parseRequest(c, &r); err != nil {
			r.releaseBuf()
			if err == io.EOF || isErrConnReset(err) || err == errClientTimeout {
				return nil
			}
			return err
		}
		path := r.URL.Path
		r.URL = &URL{HostPort: target.HostPort, Host: target.Host, Port: target.Port, Domain: target.Domain, Path: path}
		protocol := "http"
		if secure {
			protocol = "https"
		}
		if r.isWebSocket() {
			protocol = "ws"
			if secure {
				protocol = "wss"
			}
		}
		r.capture = startTrafficCapture(&r, protocol)
		err := sv.doRequest(c, &r, &rp)
		r.releaseBuf()
		r.capture.close()
		if err != nil {
			return err
		}
		if rp.Status == 101 && r.isWebSocket() {
			return nil
		}
		if !r.ConnectionKeepAlive || !rp.ConnectionKeepAlive {
			return nil
		}
	}
}

func sendCaptureCA(c *clientConn) error {
	captureCA.Lock()
	certPEM := append([]byte(nil), captureCA.certPEM...)
	captureCA.Unlock()
	if len(certPEM) == 0 {
		return errors.New("capture CA is not available")
	}
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Disposition: attachment; filename=%q\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", captureCACertName, len(certPEM))
	if _, err := c.Write([]byte(header)); err != nil {
		return err
	}
	_, err := c.Write(certPEM)
	return err
}
