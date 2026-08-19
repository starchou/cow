package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type socks5UDPTestAssociation struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr
	done    <-chan struct{}
}

func startSocks5UDPTestAssociation(t *testing.T, timeout time.Duration) *socks5UDPTestAssociation {
	t.Helper()

	oldTimeout := config.Socks5UDPTimeout
	config.Socks5UDPTimeout = timeout
	t.Cleanup(func() { config.Socks5UDPTimeout = oldTimeout })

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	listenerAddr := listener.Addr().String()

	control, err := net.Dial("tcp4", listenerAddr)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := listener.Accept()
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	listener.Close()

	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		control.Close()
		serverConn.Close()
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		newClientConn(serverConn, newSocksProxy(listenerAddr)).serveSocks()
		close(done)
	}()

	t.Cleanup(func() {
		control.Close()
		udpClient.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("SOCKS5 UDP association did not stop during cleanup")
		}
	})

	if err := control.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{socks5Version, 0x01, socks5AuthNone}); err != nil {
		t.Fatal(err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(control, methodReply[:]); err != nil {
		t.Fatal(err)
	}
	if methodReply != [2]byte{socks5Version, socks5AuthNone} {
		t.Fatalf("unexpected SOCKS5 method reply %v", methodReply)
	}

	clientAddr := udpClient.LocalAddr().(*net.UDPAddr)
	addrPort, err := buildSocks5AddrPort(clientAddr.IP.String(), uint16(clientAddr.Port))
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{socks5Version, socks5CmdUDPAssociate, 0x00}, addrPort...)
	if _, err := control.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != socks5Version || reply[1] != socks5StatusSucceeded || reply[3] != socks5AtypIPv4 {
		t.Fatalf("unexpected SOCKS5 UDP associate reply %v", reply)
	}
	relay := &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(binary.BigEndian.Uint16(reply[8:10])),
	}
	if relay.Port == 0 {
		t.Fatal("SOCKS5 UDP associate returned an empty relay port")
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	assertSocks5UDPRelayInUse(t, relay)

	return &socks5UDPTestAssociation{
		control: control,
		udp:     udpClient,
		relay:   relay,
		done:    done,
	}
}

func waitSocks5UDPTestAssociation(t *testing.T, association *socks5UDPTestAssociation, timeout time.Duration) {
	t.Helper()
	select {
	case <-association.done:
	case <-time.After(timeout):
		t.Fatalf("SOCKS5 UDP association did not stop within %v", timeout)
	}
}

func assertSocks5UDPRelayReleased(t *testing.T, relay *net.UDPAddr) {
	t.Helper()
	rebound, err := net.ListenUDP("udp4", relay)
	if err != nil {
		t.Fatalf("SOCKS5 UDP relay port %s was not released: %v", relay, err)
	}
	rebound.Close()
}

func assertSocks5UDPRelayInUse(t *testing.T, relay *net.UDPAddr) {
	t.Helper()
	probe, err := net.ListenUDP("udp4", relay)
	if err == nil {
		probe.Close()
		t.Fatalf("SOCKS5 UDP relay port %s was not held by the association", relay)
	}
}

func TestSocks5UDPAssociateIdleReleasesPort(t *testing.T) {
	association := startSocks5UDPTestAssociation(t, 100*time.Millisecond)

	waitSocks5UDPTestAssociation(t, association, 2*time.Second)
	assertSocks5UDPRelayReleased(t, association.relay)

	if err := association.control.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := association.control.Read(one[:]); err == nil {
		t.Fatal("SOCKS5 control connection remained open after UDP idle timeout")
	} else if isErrTimeout(err) {
		t.Fatal("timed out waiting for the SOCKS5 control connection to close")
	}
}

func TestSocks5UDPAssociateClientActivityRefreshesTimeout(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{}, 16)
	sinkDone := make(chan struct{})
	go func() {
		defer close(sinkDone)
		buf := make([]byte, 1024)
		for {
			_, _, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received <- struct{}{}
		}
	}()
	t.Cleanup(func() {
		sink.Close()
		<-sinkDone
	})

	const idleTimeout = 300 * time.Millisecond
	association := startSocks5UDPTestAssociation(t, idleTimeout)
	packet, err := buildSocks5UDPDatagram(sink.LocalAddr().String(), []byte("client-active"))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 14; i++ {
		if i > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		if err := association.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := association.udp.WriteToUDP(packet, association.relay); err != nil {
			t.Fatal(err)
		}
		select {
		case <-received:
		case <-time.After(time.Second):
			t.Fatal("SOCKS5 UDP client packet did not reach the remote sink")
		}
		select {
		case <-association.done:
			t.Fatal("client-active SOCKS5 UDP association closed before its idle timeout")
		default:
		}
	}
	if err := association.udp.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	waitSocks5UDPTestAssociation(t, association, 2*time.Second)
	assertSocks5UDPRelayReleased(t, association.relay)
}

func TestSocks5UDPAssociateRemoteActivityRefreshesTimeout(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { remote.Close() })

	const idleTimeout = 300 * time.Millisecond
	association := startSocks5UDPTestAssociation(t, idleTimeout)
	seed, err := buildSocks5UDPDatagram(remote.LocalAddr().String(), []byte("seed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := association.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := association.udp.WriteToUDP(seed, association.relay); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_, cowAddr, err := remote.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("remote-active")
	for i := 0; i < 14; i++ {
		if i > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		if err := remote.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := remote.WriteToUDP(payload, cowAddr); err != nil {
			t.Fatal(err)
		}
		if err := association.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := association.udp.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, gotPayload, err := parseSocks5UDPDatagram(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if string(gotPayload) != string(payload) {
			t.Fatalf("unexpected SOCKS5 UDP response payload %q", gotPayload)
		}
		select {
		case <-association.done:
			t.Fatal("remote-active SOCKS5 UDP association closed before its idle timeout")
		default:
		}
	}
	if err := association.udp.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	waitSocks5UDPTestAssociation(t, association, 2*time.Second)
	assertSocks5UDPRelayReleased(t, association.relay)
}

func TestSocks5UDPAssociateControlCloseReleasesPort(t *testing.T) {
	association := startSocks5UDPTestAssociation(t, 5*time.Second)

	if err := association.control.Close(); err != nil {
		t.Fatal(err)
	}
	waitSocks5UDPTestAssociation(t, association, time.Second)
	assertSocks5UDPRelayReleased(t, association.relay)
}

func TestSocks5UDPAssociateTimeoutDisabled(t *testing.T) {
	association := startSocks5UDPTestAssociation(t, 0)

	select {
	case <-association.done:
		t.Fatal("SOCKS5 UDP association closed with idle timeout disabled")
	case <-time.After(400 * time.Millisecond):
	}
	if err := association.control.Close(); err != nil {
		t.Fatal(err)
	}
	waitSocks5UDPTestAssociation(t, association, time.Second)
	assertSocks5UDPRelayReleased(t, association.relay)
}

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
