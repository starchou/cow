package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	socks5Version               = 0x05
	socks5AuthNone              = 0x00
	socks5AuthUserPass          = 0x02
	socks5AuthNoAcceptable      = 0xff
	socks5UserPassVersion       = 0x01
	socks5CmdConnect            = 0x01
	socks5AtypIPv4              = 0x01
	socks5AtypDomain            = 0x03
	socks5AtypIPv6              = 0x04
	socks5StatusSucceeded       = 0x00
	socks5StatusGeneralError    = 0x01
	socks5StatusConnRefused     = 0x05
	socks5StatusCmdUnsupported  = 0x07
	socks5StatusAtypUnsupported = 0x08
)

type socksProxy struct {
	addr string
}

type mixedProxy struct {
	addr  string
	http  *httpProxy
	socks *socksProxy
}

type socksRequestError struct {
	reply byte
	err   error
}

func (e socksRequestError) Error() string {
	return e.err.Error()
}

func (e socksRequestError) Unwrap() error {
	return e.err
}

func newSocksRequestError(reply byte, format string, args ...interface{}) error {
	return socksRequestError{
		reply: reply,
		err:   fmt.Errorf(format, args...),
	}
}

func newSocksProxy(addr string) *socksProxy {
	return &socksProxy{addr: addr}
}

func newMixedProxy(http *httpProxy, socks *socksProxy, addr string) *mixedProxy {
	return &mixedProxy{
		addr:  addr,
		http:  http,
		socks: socks,
	}
}

func (proxy *socksProxy) genConfig() string {
	return fmt.Sprintf("listen = socks5://%s", proxy.addr)
}

func (proxy *socksProxy) Addr() string {
	return proxy.addr
}

func (proxy *socksProxy) Serve(wg *sync.WaitGroup, quit <-chan struct{}) {
	defer wg.Done()

	ln, err := net.Listen("tcp", proxy.addr)
	if err != nil {
		log.Panicf("listen socks5 failed: %+v", err)
		return
	}

	var exit bool
	go func() {
		<-quit
		exit = true
		ln.Close()
	}()

	info.Printf("COW %s listen socks5 %s\n", version, proxy.addr)
	for {
		conn, err := ln.Accept()
		if err != nil && !exit {
			errl.Printf("socks5 proxy(%s) accept %v\n", ln.Addr(), err)
			if isErrTooManyOpenFd(err) {
				connPool.CloseAll()
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if exit {
			debug.Println("exiting the socks5 listener")
			break
		}
		c := newClientConn(conn, proxy)
		go c.serveSocks()
	}
}

func (proxy *mixedProxy) genConfig() string {
	return proxy.http.genConfig()
}

func (proxy *mixedProxy) Addr() string {
	return proxy.addr
}

func pacURLForProxy(addr, port, addrInPAC string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" {
		return fmt.Sprintf("http://<hostip>:%s/pac", port)
	}
	if addrInPAC == "" {
		return fmt.Sprintf("http://%s/pac", addr)
	}
	return fmt.Sprintf("http://%s/pac", addrInPAC)
}

func (proxy *mixedProxy) Serve(wg *sync.WaitGroup, quit <-chan struct{}) {
	defer wg.Done()

	ln, err := net.Listen("tcp", proxy.addr)
	if err != nil {
		log.Panicf("listen mixed http+socks5 failed: %+v", err)
		return
	}

	var exit bool
	go func() {
		<-quit
		exit = true
		ln.Close()
	}()

	info.Printf("COW %s listen http+socks5 %s, PAC url %s\n",
		version, proxy.addr, pacURLForProxy(proxy.addr, proxy.http.port, proxy.http.addrInPAC))

	for {
		conn, err := ln.Accept()
		if err != nil && !exit {
			errl.Printf("mixed proxy(%s) accept %v\n", ln.Addr(), err)
			if isErrTooManyOpenFd(err) {
				connPool.CloseAll()
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if exit {
			debug.Println("exiting the mixed listener")
			break
		}
		c := newClientConn(conn, proxy)
		go c.serveMixed()
	}
}

func normalizeListenHost(host string) string {
	switch host {
	case "":
		return "0.0.0.0"
	case "localhost":
		return "127.0.0.1"
	default:
		return host
	}
}

func isWildcardListenHost(host string) bool {
	host = normalizeListenHost(host)
	return host == "0.0.0.0"
}

func mixedListenAddr(httpAddr, socksAddr string) (string, bool) {
	httpHost, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return "", false
	}
	socksHost, socksPort, err := net.SplitHostPort(socksAddr)
	if err != nil || httpPort != socksPort {
		return "", false
	}

	httpHost = normalizeListenHost(httpHost)
	socksHost = normalizeListenHost(socksHost)

	switch {
	case httpHost == socksHost:
		return net.JoinHostPort(httpHost, httpPort), true
	case isWildcardListenHost(httpHost):
		return net.JoinHostPort(httpHost, httpPort), true
	case isWildcardListenHost(socksHost):
		return net.JoinHostPort(socksHost, httpPort), true
	default:
		return "", false
	}
}

func mergeListenProxies(proxies []Proxy) []Proxy {
	used := make([]bool, len(proxies))
	merged := make([]Proxy, 0, len(proxies))

	for i, proxy := range proxies {
		if used[i] {
			continue
		}

		switch p := proxy.(type) {
		case *httpProxy:
			if mp, idx := matchSocksProxy(p, proxies, used); mp != nil {
				used[idx] = true
				merged = append(merged, mp)
				continue
			}
		case *socksProxy:
			if mp, idx := matchHTTPProxy(p, proxies, used); mp != nil {
				used[idx] = true
				merged = append(merged, mp)
				continue
			}
		}
		merged = append(merged, proxy)
	}

	return merged
}

func matchSocksProxy(http *httpProxy, proxies []Proxy, used []bool) (*mixedProxy, int) {
	for i, proxy := range proxies {
		if used[i] {
			continue
		}
		socks, ok := proxy.(*socksProxy)
		if !ok {
			continue
		}
		if addr, ok := mixedListenAddr(http.addr, socks.addr); ok {
			return newMixedProxy(http, socks, addr), i
		}
	}
	return nil, -1
}

func matchHTTPProxy(socks *socksProxy, proxies []Proxy, used []bool) (*mixedProxy, int) {
	for i, proxy := range proxies {
		if used[i] {
			continue
		}
		http, ok := proxy.(*httpProxy)
		if !ok {
			continue
		}
		if addr, ok := mixedListenAddr(http.addr, socks.addr); ok {
			return newMixedProxy(http, socks, addr), i
		}
	}
	return nil, -1
}

func (c *clientConn) serveMixed() {
	b, err := c.bufRd.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	if b[0] == socks5Version {
		c.serveSocks()
		return
	}
	c.serve()
}

func (c *clientConn) remoteIP() string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func hasByte(items []byte, needle byte) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func (c *clientConn) socksNoAuthAllowed() bool {
	if !auth.required {
		return true
	}
	clientIP := c.remoteIP()
	if clientIP == "" {
		return false
	}
	if auth.authed != nil && auth.authed.has(clientIP) {
		return true
	}
	return authIP(clientIP)
}

func (c *clientConn) writeSocks5Method(method byte) error {
	_, err := c.Write([]byte{socks5Version, method})
	return err
}

func (c *clientConn) writeSocks5UserPassStatus(status byte) error {
	_, err := c.Write([]byte{socks5UserPassVersion, status})
	return err
}

func (c *clientConn) authSocksUserPass() error {
	var header [2]byte
	if _, err := io.ReadFull(c.bufRd, header[:]); err != nil {
		return err
	}
	if header[0] != socks5UserPassVersion {
		if err := c.writeSocks5UserPassStatus(0x01); err != nil {
			return err
		}
		return errAuthRequired
	}

	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c.bufRd, user); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(c.bufRd, plen[:]); err != nil {
		return err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c.bufRd, passwd); err != nil {
		return err
	}

	au, ok := auth.user[string(user)]
	if !ok || au.passwd != string(passwd) {
		if err := c.writeSocks5UserPassStatus(0x01); err != nil {
			return err
		}
		return errAuthRequired
	}
	if err := authPort(c, string(user), au); err != nil {
		if writeErr := c.writeSocks5UserPassStatus(0x01); writeErr != nil {
			return writeErr
		}
		return err
	}
	if err := c.writeSocks5UserPassStatus(0x00); err != nil {
		return err
	}
	clientIP := c.remoteIP()
	if clientIP != "" && auth.authed != nil {
		auth.authed.add(clientIP)
	}
	return nil
}

func (c *clientConn) negotiateSocks5() error {
	var header [2]byte
	if _, err := io.ReadFull(c.bufRd, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return newSocksRequestError(socks5StatusGeneralError, "unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c.bufRd, methods); err != nil {
		return err
	}

	if c.socksNoAuthAllowed() && hasByte(methods, socks5AuthNone) {
		return c.writeSocks5Method(socks5AuthNone)
	}
	if len(auth.user) > 0 && hasByte(methods, socks5AuthUserPass) {
		if err := c.writeSocks5Method(socks5AuthUserPass); err != nil {
			return err
		}
		return c.authSocksUserPass()
	}
	if err := c.writeSocks5Method(socks5AuthNoAcceptable); err != nil {
		return err
	}
	return errAuthRequired
}

func (c *clientConn) readSocks5Target(atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case socks5AtypIPv4:
		var addr [4]byte
		if _, err = io.ReadFull(c.bufRd, addr[:]); err != nil {
			return
		}
		host = net.IP(addr[:]).String()
	case socks5AtypIPv6:
		var addr [16]byte
		if _, err = io.ReadFull(c.bufRd, addr[:]); err != nil {
			return
		}
		host = net.IP(addr[:]).String()
	case socks5AtypDomain:
		var size [1]byte
		if _, err = io.ReadFull(c.bufRd, size[:]); err != nil {
			return
		}
		domain := make([]byte, int(size[0]))
		if _, err = io.ReadFull(c.bufRd, domain); err != nil {
			return
		}
		host = string(domain)
	default:
		err = newSocksRequestError(socks5StatusAtypUnsupported, "unsupported socks address type %d", atyp)
		return
	}

	var portBytes [2]byte
	if _, err = io.ReadFull(c.bufRd, portBytes[:]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBytes[:])
	return
}

func (c *clientConn) parseSocks5Request(r *Request) error {
	var header [4]byte
	if _, err := io.ReadFull(c.bufRd, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return newSocksRequestError(socks5StatusGeneralError, "unsupported socks version %d", header[0])
	}
	if header[1] != socks5CmdConnect {
		return newSocksRequestError(socks5StatusCmdUnsupported, "unsupported socks command %d", header[1])
	}

	host, port, err := c.readSocks5Target(header[3])
	if err != nil {
		return err
	}

	r.reset()
	r.Method = "CONNECT"
	r.isConnect = true
	r.URL = &URL{}
	r.URL.ParseHostPort(net.JoinHostPort(host, strconv.Itoa(int(port))))
	r.Header.Host = r.URL.HostPort
	return nil
}

func buildSocks5Reply(reply byte, addr net.Addr) []byte {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			resp := []byte{socks5Version, reply, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
			copy(resp[4:8], ip4)
			binary.BigEndian.PutUint16(resp[8:10], uint16(tcpAddr.Port))
			return resp
		}
		if ip6 := tcpAddr.IP.To16(); ip6 != nil {
			resp := make([]byte, 22)
			resp[0] = socks5Version
			resp[1] = reply
			resp[2] = 0x00
			resp[3] = socks5AtypIPv6
			copy(resp[4:20], ip6)
			binary.BigEndian.PutUint16(resp[20:22], uint16(tcpAddr.Port))
			return resp
		}
	}
	return []byte{socks5Version, reply, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
}

func (c *clientConn) writeSocks5Reply(reply byte, addr net.Addr) error {
	_, err := c.Write(buildSocks5Reply(reply, addr))
	return err
}

func socksReplyFromError(err error) byte {
	if err == nil {
		return socks5StatusSucceeded
	}
	var reqErr socksRequestError
	if errors.As(err, &reqErr) {
		return reqErr.reply
	}
	if isErrTimeout(err) || isErrConnReset(err) {
		return socks5StatusGeneralError
	}
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return socks5StatusConnRefused
	}
	return socks5StatusGeneralError
}

func (c *clientConn) createSocksServerConn(r *Request, siteInfo *VisitCnt) (*serverConn, error) {
	srvconn, err := c.connectServer(r, siteInfo, false)
	if err != nil {
		return nil, err
	}
	sv := newServerConn(srvconn, r.URL.HostPort, siteInfo)
	if debug {
		debug.Printf("cli(%s) socks5 connected to %s %d concurrent connections\n",
			c.RemoteAddr(), sv.hostPort, incSrvConnCnt(sv.hostPort))
	}
	return sv, nil
}

func buildParentSocksConnectRequest(r *Request, authHeader []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("CONNECT ")
	buf.WriteString(r.URL.HostPort)
	buf.WriteString(" HTTP/1.1\r\n")
	buf.WriteString("Host: ")
	buf.WriteString(r.URL.HostPort)
	buf.WriteString(CRLF)
	if len(authHeader) != 0 {
		buf.Write(authHeader)
	}
	buf.WriteString(fullHeaderConnectionKeepAlive)
	buf.WriteString(CRLF)
	return buf.Bytes()
}

func (sv *serverConn) establishParentConnect(r *Request, c *clientConn) error {
	_, isHTTPConn := sv.Conn.(httpConn)
	_, isCowConn := sv.Conn.(cowConn)
	if !isHTTPConn && !isCowConn {
		return nil
	}
	var authHeader []byte
	if hc, ok := sv.Conn.(httpConn); ok {
		authHeader = hc.parent.authHeader
	}
	if _, err := sv.Write(buildParentSocksConnectRequest(r, authHeader)); err != nil {
		return err
	}

	sv.initBuf()
	var rp Response
	if err := parseResponse(sv, r, &rp); err != nil {
		return err
	}
	defer rp.releaseBuf()

	if rp.Status != 200 {
		return newSocksRequestError(socks5StatusGeneralError,
			"parent proxy connect failed: %s", rp.String())
	}
	return nil
}

func (sv *serverConn) tunnel(r *Request, c *clientConn) (err error) {
	var cli2srvErr error
	done := make(chan struct{})
	srvStopped := newNotification()
	go func() {
		cli2srvErr = copyClient2Server(c, sv, r, srvStopped, done)
		sv.Close()
	}()

	err = copyServer2Client(sv, c, r)
	if isErrRetry(err) {
		srvStopped.notify()
		<-done
	} else {
		c.Conn.Close()
	}
	if isErrRetry(cli2srvErr) {
		return cli2srvErr
	}
	return err
}

func (sv *serverConn) doSocksConnect(r *Request, c *clientConn) error {
	r.state = rsCreated
	if err := sv.establishParentConnect(r, c); err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return err
	}
	if err := c.writeSocks5Reply(socks5StatusSucceeded, sv.LocalAddr()); err != nil {
		return err
	}
	return sv.tunnel(r, c)
}

func (c *clientConn) serveSocks() {
	var r Request
	defer func() {
		r.releaseBuf()
		c.Close()
	}()

	if err := c.negotiateSocks5(); err != nil {
		if err != errAuthRequired && debug {
			debug.Printf("cli(%s) socks5 negotiate %v\n", c.RemoteAddr(), err)
		}
		return
	}
	if err := c.parseSocks5Request(&r); err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return
	}

	siteInfo := siteStat.GetVisitCnt(r.URL)
	sv, err := c.createSocksServerConn(&r, siteInfo)
	if err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return
	}
	sv.doSocksConnect(&r, c)
}
