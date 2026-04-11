package main

import (
	"errors"
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
