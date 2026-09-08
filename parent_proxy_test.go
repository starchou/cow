package main

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type stubParentProxy struct {
	server string
	err    error
}

func (s stubParentProxy) connect(*URL) (net.Conn, error) {
	if s.err != nil {
		return nil, s.err
	}
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

func (s stubParentProxy) getServer() string {
	return s.server
}

func (s stubParentProxy) genConfig() string {
	return s.server
}

func TestLatencyParentPoolDemotesFailingProxy(t *testing.T) {
	oldParentProxy := parentProxy
	defer func() {
		parentProxy = oldParentProxy
	}()

	pp := &latencyParentPool{
		parent: []ParentWithLatency{
			{ParentProxy: stubParentProxy{server: "bad:1", err: errors.New("boom")}, latency: time.Millisecond},
			{ParentProxy: stubParentProxy{server: "good:2"}, latency: 2 * time.Millisecond},
		},
	}
	parentProxy = pp

	conn, err := pp.connect(&URL{Host: "example.com"})
	if err != nil {
		t.Fatalf("expected fallback proxy to succeed, got %v", err)
	}
	conn.Close()

	if pp.parent[0].latency != latencyMax {
		t.Fatalf("failing proxy should be demoted to latencyMax, got %v", pp.parent[0].latency)
	}
}

func TestHTTPParentPoolUpdateAvailable(t *testing.T) {
	pool := newHTTPParentPool()
	a := newHttpParent("a:1")
	b := newHttpParent("b:2")
	c := newHttpParent("c:3")
	pool.add(a)
	pool.add(b)
	pool.add(c)

	pool.probe = func(parent *httpParent) (time.Duration, error) {
		switch parent.server {
		case "a:1":
			return 30 * time.Millisecond, nil
		case "b:2":
			return latencyMax, errors.New("down")
		case "c:3":
			return 10 * time.Millisecond, nil
		default:
			return latencyMax, errors.New("unexpected parent")
		}
	}

	pool.updateAvailable()

	available := pool.snapshotAvailable()
	if len(available) != 2 {
		t.Fatalf("want 2 available parents, got %d", len(available))
	}
	if available[0].parent.server != "c:3" {
		t.Fatalf("lowest latency parent should be c:3, got %s", available[0].parent.server)
	}
	if available[1].parent.server != "a:1" {
		t.Fatalf("second lowest latency parent should be a:1, got %s", available[1].parent.server)
	}
}

func TestConnectInOrderUsesHTTPParentPool(t *testing.T) {
	oldHTTPPool := parentHTTPPool
	defer func() {
		parentHTTPPool = oldHTTPPool
	}()

	pool := newHTTPParentPool()
	bad := newHttpParent("bad:1")
	good := newHttpParent("good:2")
	pool.add(bad)
	pool.add(good)

	pool.probe = func(parent *httpParent) (time.Duration, error) {
		switch parent.server {
		case "bad:1":
			return 5 * time.Millisecond, nil
		case "good:2":
			return 10 * time.Millisecond, nil
		default:
			return latencyMax, errors.New("unexpected parent")
		}
	}
	pool.dial = func(parent *httpParent, url *URL) (net.Conn, error) {
		if parent.server == "bad:1" {
			return nil, errors.New("connect failed")
		}
		c1, c2 := net.Pipe()
		c2.Close()
		return c1, nil
	}
	parentHTTPPool = pool

	parents := []ParentWithFail{
		{ParentProxy: bad},
		{ParentProxy: good},
	}
	conn, err := connectInOrder(&URL{HostPort: "example.com:80"}, parents, 0)
	if err != nil {
		t.Fatalf("expected http parent pool to find a healthy parent, got %v", err)
	}
	conn.Close()

	available := pool.snapshotAvailable()
	if len(available) != 1 || available[0].parent.server != "good:2" {
		t.Fatalf("bad parent should be removed from available list, got %+v", available)
	}
}

func TestSocksParentConnectReadsVariableLengthReply(t *testing.T) {
	oldDial := socksParentDial
	defer func() {
		socksParentDial = oldDial
	}()

	errCh := make(chan error, 1)
	clientSide, parentSide := net.Pipe()
	socksParentDial = func(network, address string) (net.Conn, error) {
		return clientSide, nil
	}

	go func() {
		defer parentSide.Close()
		method := make([]byte, 3)
		if _, err := io.ReadFull(parentSide, method); err != nil {
			errCh <- err
			return
		}
		if _, err := parentSide.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
			errCh <- err
			return
		}

		reqHead := make([]byte, 5)
		if _, err := io.ReadFull(parentSide, reqHead); err != nil {
			errCh <- err
			return
		}
		target := make([]byte, int(reqHead[4])+2)
		if _, err := io.ReadFull(parentSide, target); err != nil {
			errCh <- err
			return
		}

		reply := []byte{
			socks5Version, 0, 0, socks5AtypIPv6,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0x12, 0x34,
		}
		reply = append(reply, []byte("payload")...)
		if _, err := parentSide.Write(reply); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	sp := newSocksParent("127.0.0.1:1080")
	conn, err := sp.connect(&URL{
		Host:     "example.com",
		Port:     "443",
		HostPort: "example.com:443",
	})
	if err != nil {
		t.Fatalf("connect returned error: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, len("payload"))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(payload) != "payload" {
		t.Fatalf("socks reply bytes leaked into tunnel, got %q", payload)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("fake socks parent error: %v", err)
	}
}

func TestSocksParentUsernamePasswordAuthentication(t *testing.T) {
	oldDial := socksParentDial
	defer func() { socksParentDial = oldDial }()

	clientSide, parentSide := net.Pipe()
	socksParentDial = func(network, address string) (net.Conn, error) { return clientSide, nil }
	errCh := make(chan error, 1)
	go func() {
		defer parentSide.Close()
		var method [3]byte
		if _, err := io.ReadFull(parentSide, method[:]); err != nil {
			errCh <- err
			return
		}
		if method != [3]byte{socks5Version, 1, socks5AuthUserPass} {
			errCh <- errors.New("client did not request username/password authentication")
			return
		}
		if _, err := parentSide.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
			errCh <- err
			return
		}

		var authHeader [2]byte
		if _, err := io.ReadFull(parentSide, authHeader[:]); err != nil {
			errCh <- err
			return
		}
		username := make([]byte, int(authHeader[1]))
		if _, err := io.ReadFull(parentSide, username); err != nil {
			errCh <- err
			return
		}
		var passwordLength [1]byte
		if _, err := io.ReadFull(parentSide, passwordLength[:]); err != nil {
			errCh <- err
			return
		}
		password := make([]byte, int(passwordLength[0]))
		if _, err := io.ReadFull(parentSide, password); err != nil {
			errCh <- err
			return
		}
		if authHeader[0] != socks5UserPassVersion || string(username) != "alice" || string(password) != "s3:cret" {
			errCh <- errors.New("wrong SOCKS5 credentials")
			return
		}
		if _, err := parentSide.Write([]byte{socks5UserPassVersion, 0}); err != nil {
			errCh <- err
			return
		}

		reqHead := make([]byte, 5)
		if _, err := io.ReadFull(parentSide, reqHead); err != nil {
			errCh <- err
			return
		}
		target := make([]byte, int(reqHead[4])+2)
		if _, err := io.ReadFull(parentSide, target); err != nil {
			errCh <- err
			return
		}
		reply := []byte{socks5Version, 0, 0, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
		_, err := parentSide.Write(reply)
		errCh <- err
	}()

	sp := newSocksParentAuth("127.0.0.1:1080", "alice", "s3:cret")
	conn, err := sp.connect(&URL{Host: "example.com", Port: "443", HostPort: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
