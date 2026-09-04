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
	socks5CmdUDPAssociate       = 0x03
	socks5AtypIPv4              = 0x01
	socks5AtypDomain            = 0x03
	socks5AtypIPv6              = 0x04
	socks5StatusSucceeded       = 0x00
	socks5StatusGeneralError    = 0x01
	socks5StatusConnRefused     = 0x05
	socks5StatusCmdUnsupported  = 0x07
	socks5StatusAtypUnsupported = 0x08
	socks5UDPBufferSize         = 65535
	defaultSocks5UDPIdleTimeout = 5 * time.Minute
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

type socks5ParsedRequest struct {
	cmd      byte
	host     string
	port     uint16
	hostPort string
}

func (c *clientConn) parseSocks5Request(r *Request) (req socks5ParsedRequest, err error) {
	var header [4]byte
	if _, err = io.ReadFull(c.bufRd, header[:]); err != nil {
		return
	}
	if header[0] != socks5Version {
		err = newSocksRequestError(socks5StatusGeneralError, "unsupported socks version %d", header[0])
		return
	}
	if header[2] != 0x00 {
		err = newSocksRequestError(socks5StatusGeneralError, "invalid socks reserved byte %d", header[2])
		return
	}
	if header[1] != socks5CmdConnect && header[1] != socks5CmdUDPAssociate {
		err = newSocksRequestError(socks5StatusCmdUnsupported, "unsupported socks command %d", header[1])
		return
	}

	host, port, err := c.readSocks5Target(header[3])
	if err != nil {
		return
	}

	req.cmd = header[1]
	req.host = host
	req.port = port
	req.hostPort = net.JoinHostPort(host, strconv.Itoa(int(port)))

	if req.cmd == socks5CmdConnect {
		r.reset()
		r.Method = "CONNECT"
		r.isConnect = true
		r.URL = &URL{}
		r.URL.ParseHostPort(req.hostPort)
		r.Header.Host = r.URL.HostPort
	}
	return
}

func trimIPv6Zone(host string) string {
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		return host[:i]
	}
	return host
}

func buildSocks5AddrPort(host string, port uint16) ([]byte, error) {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ipHost := trimIPv6Zone(host)

	var buf bytes.Buffer
	if ip := net.ParseIP(ipHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(socks5AtypIPv4)
			buf.Write(ip4)
		} else if ip16 := ip.To16(); ip16 != nil {
			buf.WriteByte(socks5AtypIPv6)
			buf.Write(ip16)
		} else {
			return nil, fmt.Errorf("invalid socks5 ip %q", host)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid socks5 host %q", host)
		}
		buf.WriteByte(socks5AtypDomain)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	buf.Write(portBytes[:])
	return buf.Bytes(), nil
}

func buildSocks5Reply(reply byte, addr net.Addr) []byte {
	ip := net.IPv4zero
	port := 0
	zone := ""
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.IP != nil {
			ip = a.IP
		}
		port = a.Port
		zone = a.Zone
	case *net.UDPAddr:
		if a.IP != nil {
			ip = a.IP
		}
		port = a.Port
		zone = a.Zone
	}

	if port < 0 || port > 0xffff {
		port = 0
	}
	host := ip.String()
	if zone != "" && ip.To4() == nil {
		host += "%" + zone
	}
	addrPort, err := buildSocks5AddrPort(host, uint16(port))
	if err != nil {
		addrPort = []byte{socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	}
	resp := make([]byte, 0, 3+len(addrPort))
	resp = append(resp, socks5Version, reply, 0x00)
	resp = append(resp, addrPort...)
	return resp
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

func isZeroIP(ip net.IP) bool {
	return ip == nil || ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero)
}

func listenSocks5UDPRelay(tcpLocal net.Addr) (*net.UDPConn, error) {
	var ip net.IP
	var zone string
	if tcpAddr, ok := tcpLocal.(*net.TCPAddr); ok {
		ip = tcpAddr.IP
		zone = tcpAddr.Zone
	}

	network := "udp"
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		network = "udp6"
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: 0, Zone: zone})
}

func socks5UDPReplyAddr(tcpLocal net.Addr, udpLocal *net.UDPAddr) net.Addr {
	if udpLocal == nil {
		return nil
	}
	if tcpAddr, ok := tcpLocal.(*net.TCPAddr); ok && !isZeroIP(tcpAddr.IP) {
		return &net.UDPAddr{IP: tcpAddr.IP, Port: udpLocal.Port, Zone: tcpAddr.Zone}
	}
	return udpLocal
}

func sameSocks5UDPClient(tcpPeerIP string, current, expected *net.UDPAddr) bool {
	if current == nil {
		return false
	}
	if expected != nil {
		return current.IP.Equal(expected.IP) && current.Port == expected.Port && current.Zone == expected.Zone
	}
	if tcpPeerIP == "" {
		return true
	}
	peerIP := net.ParseIP(tcpPeerIP)
	return peerIP != nil && current.IP.Equal(peerIP)
}

func parseSocks5UDPDatagram(packet []byte) (target string, payload []byte, err error) {
	if len(packet) < 4 {
		return "", nil, newSocksRequestError(socks5StatusGeneralError, "socks5 udp packet too short")
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return "", nil, newSocksRequestError(socks5StatusGeneralError, "invalid socks5 udp reserved field")
	}
	if packet[2] != 0x00 {
		return "", nil, newSocksRequestError(socks5StatusCmdUnsupported, "socks5 udp fragment is not supported")
	}

	off := 4
	var host string
	switch packet[3] {
	case socks5AtypIPv4:
		if len(packet) < off+net.IPv4len+2 {
			return "", nil, newSocksRequestError(socks5StatusGeneralError, "socks5 udp ipv4 packet too short")
		}
		host = net.IP(packet[off : off+net.IPv4len]).String()
		off += net.IPv4len
	case socks5AtypIPv6:
		if len(packet) < off+net.IPv6len+2 {
			return "", nil, newSocksRequestError(socks5StatusGeneralError, "socks5 udp ipv6 packet too short")
		}
		host = net.IP(packet[off : off+net.IPv6len]).String()
		off += net.IPv6len
	case socks5AtypDomain:
		if len(packet) < off+1 {
			return "", nil, newSocksRequestError(socks5StatusGeneralError, "socks5 udp domain length missing")
		}
		size := int(packet[off])
		off++
		if size == 0 || len(packet) < off+size+2 {
			return "", nil, newSocksRequestError(socks5StatusGeneralError, "socks5 udp domain packet too short")
		}
		host = string(packet[off : off+size])
		off += size
	default:
		return "", nil, newSocksRequestError(socks5StatusAtypUnsupported, "unsupported socks5 udp address type %d", packet[3])
	}

	port := binary.BigEndian.Uint16(packet[off : off+2])
	off += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), packet[off:], nil
}

func buildSocks5UDPDatagram(addr string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 0xffff {
		return nil, fmt.Errorf("invalid udp port %q", portStr)
	}
	addrPort, err := buildSocks5AddrPort(host, uint16(port))
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(payload)+3+len(addrPort)))
	buf.Write([]byte{0x00, 0x00, 0x00})
	buf.Write(addrPort)
	buf.Write(payload)
	return buf.Bytes(), nil
}

func refreshSocks5UDPReadDeadline(timeout time.Duration, conn *net.UDPConn) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func (c *clientConn) serveSocksUDPAssociate(req socks5ParsedRequest) error {
	relayConn, err := listenSocks5UDPRelay(c.LocalAddr())
	if err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return err
	}
	outConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		relayConn.Close()
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return err
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			// Publish shutdown before closing sockets so blocked readers recognize
			// the resulting errors as an expected association close.
			close(done)
			c.Conn.Close()
			relayConn.Close()
			outConn.Close()
		})
	}
	var workers sync.WaitGroup
	defer func() {
		closeAll()
		workers.Wait()
	}()
	idleTimeout := config.Socks5UDPTimeout
	var deadlineMu sync.Mutex
	touch := func() error {
		deadlineMu.Lock()
		defer deadlineMu.Unlock()
		// The relay read loop owns association expiry and closes every socket.
		// Refreshing one deadline avoids a timer and two deadline updates per
		// packet while activity from either direction still keeps it alive.
		return refreshSocks5UDPReadDeadline(idleTimeout, relayConn)
	}

	udpLocal, _ := relayConn.LocalAddr().(*net.UDPAddr)
	if err := c.writeSocks5Reply(socks5StatusSucceeded, socks5UDPReplyAddr(c.LocalAddr(), udpLocal)); err != nil {
		return err
	}
	if debug {
		debug.Printf("cli(%s) socks5 udp associate %s -> relay %s\n", c.RemoteAddr(), req.hostPort, relayConn.LocalAddr())
	}
	if err := touch(); err != nil {
		return err
	}

	workers.Add(2)
	go func() {
		defer workers.Done()
		var one [1]byte
		for {
			if _, err := c.bufRd.Read(one[:]); err != nil {
				closeAll()
				return
			}
		}
	}()

	clientIP, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	var clientMu sync.RWMutex
	var clientAddr *net.UDPAddr
	setClientAddr := func(addr *net.UDPAddr) {
		clientMu.Lock()
		if clientAddr == nil {
			clientAddr = addr
		}
		clientMu.Unlock()
	}
	getClientAddr := func() *net.UDPAddr {
		clientMu.RLock()
		addr := clientAddr
		clientMu.RUnlock()
		return addr
	}

	go func() {
		defer workers.Done()
		buf := make([]byte, socks5UDPBufferSize)
		for {
			n, remoteAddr, err := outConn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				debug.Printf("cli(%s) socks5 udp read remote %v\n", c.RemoteAddr(), err)
				closeAll()
				return
			}
			addr := getClientAddr()
			if addr == nil {
				continue
			}
			packet, err := buildSocks5UDPDatagram(remoteAddr.String(), buf[:n])
			if err != nil {
				if debug {
					debug.Printf("cli(%s) socks5 udp build reply from %s: %v\n", c.RemoteAddr(), remoteAddr, err)
				}
				continue
			}
			if _, err := relayConn.WriteToUDP(packet, addr); err != nil {
				select {
				case <-done:
					return
				default:
				}
				if debug {
					debug.Printf("cli(%s) socks5 udp write client %v\n", c.RemoteAddr(), err)
				}
				continue
			}
			if err := touch(); err != nil {
				closeAll()
				return
			}
		}
	}()

	buf := make([]byte, socks5UDPBufferSize)
	for {
		n, srcAddr, err := relayConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			if isErrTimeout(err) {
				debug.Printf("cli(%s) close idle socks5 udp association after %v\n", c.RemoteAddr(), idleTimeout)
				return nil
			}
			return err
		}
		expected := getClientAddr()
		if !sameSocks5UDPClient(clientIP, srcAddr, expected) {
			if debug {
				debug.Printf("cli(%s) drop socks5 udp packet from unexpected addr %s\n", c.RemoteAddr(), srcAddr)
			}
			continue
		}
		setClientAddr(srcAddr)

		target, payload, err := parseSocks5UDPDatagram(buf[:n])
		if err != nil {
			if debug {
				debug.Printf("cli(%s) parse socks5 udp packet from %s: %v\n", c.RemoteAddr(), srcAddr, err)
			}
			continue
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			if debug {
				debug.Printf("cli(%s) resolve socks5 udp target %s: %v\n", c.RemoteAddr(), target, err)
			}
			continue
		}
		if _, err := outConn.WriteToUDP(payload, remoteAddr); err != nil {
			if debug {
				debug.Printf("cli(%s) forward socks5 udp to %s: %v\n", c.RemoteAddr(), remoteAddr, err)
			}
			continue
		}
		if err := touch(); err != nil {
			select {
			case <-done:
				return nil
			default:
			}
			return err
		}
	}
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
	activity := newTunnelWatchdog(config.TunnelTimeout, c.Conn, sv.Conn)
	defer activity.stop()
	go func() {
		defer close(done)
		cli2srvErr = copyClient2Server(c, sv, r, srvStopped, activity)
		sv.Close()
	}()

	err = copyServer2Client(sv, c, r, activity)
	if isErrRetry(err) {
		srvStopped.notify()
		<-done
	} else {
		c.Conn.Close()
		sv.Conn.Close()
		<-done
	}
	if isErrRetry(cli2srvErr) {
		return cli2srvErr
	}
	return err
}

func (sv *serverConn) doSocksConnect(r *Request, c *clientConn) error {
	r.setState(rsCreated)
	if err := sv.establishParentConnect(r, c); err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return err
	}
	if err := c.writeSocks5Reply(socks5StatusSucceeded, sv.LocalAddr()); err != nil {
		return err
	}
	if config.Capture && captureDomainAllowed(r.URL.Host) {
		return sv.doCaptureSocks(r, c)
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
	req, err := c.parseSocks5Request(&r)
	if err != nil {
		c.writeSocks5Reply(socksReplyFromError(err), nil)
		return
	}

	if req.cmd == socks5CmdUDPAssociate {
		if err := c.serveSocksUDPAssociate(req); err != nil && debug {
			debug.Printf("cli(%s) socks5 udp associate %v\n", c.RemoteAddr(), err)
		}
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
