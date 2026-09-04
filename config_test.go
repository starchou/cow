package main

import (
	"flag"
	"io"
	"os"
	"testing"
	"time"
)

func TestParseListen(t *testing.T) {
	oldListenProxy := listenProxy
	oldCmdHasListenAddr := cmdHasListenAddr
	defer func() {
		listenProxy = oldListenProxy
		cmdHasListenAddr = oldCmdHasListenAddr
	}()

	listenProxy = nil
	cmdHasListenAddr = false

	parser := configParser{}
	parser.ParseListen("http://127.0.0.1:8888")

	hp, ok := listenProxy[0].(*httpProxy)
	if !ok {
		t.Error("listen http proxy type wrong")
	}
	if hp.addr != "127.0.0.1:8888" {
		t.Error("listen http server address parse error")
	}

	parser.ParseListen("http://127.0.0.1:8888 1.2.3.4:5678")
	hp, ok = listenProxy[1].(*httpProxy)
	if hp.addrInPAC != "1.2.3.4:5678" {
		t.Error("listen http addrInPAC parse error")
	}
}

func TestParseCmdLineConfigVersionDoesNotRequireRc(t *testing.T) {
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	}()

	missingRc := "/path/to/missing/cow/rc"
	os.Args = []string{"cow", "-version", "-rc", missingRc}
	flag.CommandLine = flag.NewFlagSet("cow", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	cmdLineConfig := parseCmdLineConfig()
	if !cmdLineConfig.PrintVer {
		t.Fatal("-version should enable version output")
	}
	if cmdLineConfig.RcFile != missingRc {
		t.Fatalf("-version should not normalize or check rc file, got %s", cmdLineConfig.RcFile)
	}
}

func TestParseListenSocks5(t *testing.T) {
	oldListenProxy := listenProxy
	oldCmdHasListenAddr := cmdHasListenAddr
	defer func() {
		listenProxy = oldListenProxy
		cmdHasListenAddr = oldCmdHasListenAddr
	}()

	listenProxy = nil
	cmdHasListenAddr = false

	parser := configParser{}
	parser.ParseListen("socks5://127.0.0.1:9999")

	sp, ok := listenProxy[0].(*socksProxy)
	if !ok {
		t.Fatal("listen socks5 proxy type wrong")
	}
	if sp.addr != "127.0.0.1:9999" {
		t.Fatalf("listen socks5 server address parse error, got %s", sp.addr)
	}

	listenProxy = nil
	parser.ParseListen("sock5://127.0.0.1:9998")

	sp, ok = listenProxy[0].(*socksProxy)
	if !ok {
		t.Fatal("listen sock5 alias proxy type wrong")
	}
	if sp.addr != "127.0.0.1:9998" {
		t.Fatalf("listen sock5 alias address parse error, got %s", sp.addr)
	}
}

func TestTunnelAllowedPort(t *testing.T) {
	initConfig("")
	delete(config.TunnelAllowedPort, "*")
	parser := configParser{}
	parser.ParseTunnelAllowedPort("1, 2, 3, 4, 5")
	parser.ParseTunnelAllowedPort("6")
	parser.ParseTunnelAllowedPort("7")
	parser.ParseTunnelAllowedPort("8")

	testData := []struct {
		port    string
		allowed bool
	}{
		{"80", false},
		{"443", false},
		{"1", true},
		{"3", true},
		{"5", true},
		{"7", true},
		{"8080", false},
		{"8388", false},
	}

	for _, td := range testData {
		allowed := portAllowed(td.port)
		if allowed != td.allowed {
			t.Errorf("port %s allowed %v, got %v\n", td.port, td.allowed, allowed)
		}
	}
}

func TestTunnelAllowedPortWildcard(t *testing.T) {
	initConfig("")
	if !portAllowed("80") {
		t.Fatal("default wildcard tunnel setting should allow port 80")
	}
	if !portAllowed("8388") {
		t.Fatal("default wildcard tunnel setting should allow arbitrary ports")
	}
}

func TestParseTunnelTimeout(t *testing.T) {
	initConfig("")
	parser := configParser{}
	parser.ParseTunnelTimeout("3m")
	if config.TunnelTimeout != 3*time.Minute {
		t.Fatalf("tunnelTimeout parse error, got %v", config.TunnelTimeout)
	}
}

func TestParseCapture(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	initConfig("/tmp/cow/rc")
	if config.Capture {
		t.Fatal("capture should be disabled by default")
	}
	if config.CaptureDir != "/tmp/cow/capture" {
		t.Fatalf("unexpected default capture dir: %s", config.CaptureDir)
	}
	parser := configParser{}
	parser.ParseCapture("true")
	parser.ParseCaptureDir("~/captures")
	parser.ParseCaptureDomainFile("~/.cow/domain.list")
	if !config.Capture || config.CaptureDir == "~/captures" || config.CaptureDomainFile == "~/.cow/domain.list" {
		t.Fatalf("capture config was not parsed: %+v", config)
	}
}

func TestParseSocks5UDPTimeout(t *testing.T) {
	oldConfig := config
	defer func() { config = oldConfig }()

	initConfig("")
	if config.Socks5UDPTimeout != 5*time.Minute {
		t.Fatalf("default socks5UDPTimeout should be 5m, got %v", config.Socks5UDPTimeout)
	}
	parser := configParser{}
	parser.ParseSocks5UDPTimeout("7m")
	if config.Socks5UDPTimeout != 7*time.Minute {
		t.Fatalf("socks5UDPTimeout parse error, got %v", config.Socks5UDPTimeout)
	}
}

func TestParseProxy(t *testing.T) {
	pool, ok := parentProxy.(*backupParentPool)
	if !ok {
		t.Fatal("parentPool by default should be backup pool")
	}
	cnt := -1

	var parser configParser
	parser.ParseProxy("http://127.0.0.1:8080")
	cnt++

	hp, ok := pool.parent[cnt].ParentProxy.(*httpParent)
	if !ok {
		t.Fatal("1st http proxy parsed not as httpParent")
	}
	if hp.server != "127.0.0.1:8080" {
		t.Error("1st http proxy server address wrong, got:", hp.server)
	}

	parser.ParseProxy("http://user:passwd@127.0.0.2:9090")
	cnt++
	hp, ok = pool.parent[cnt].ParentProxy.(*httpParent)
	if !ok {
		t.Fatal("2nd http proxy parsed not as httpParent")
	}
	if hp.server != "127.0.0.2:9090" {
		t.Error("2nd http proxy server address wrong, got:", hp.server)
	}
	if hp.authHeader == nil {
		t.Error("2nd http proxy server user password not parsed")
	}

	parser.ParseProxy("socks5://127.0.0.1:1080")
	cnt++
	sp, ok := pool.parent[cnt].ParentProxy.(*socksParent)
	if !ok {
		t.Fatal("socks proxy parsed not as socksParent")
	}
	if sp.server != "127.0.0.1:1080" {
		t.Error("socks server address wrong, got:", sp.server)
	}

	parser.ParseProxy("sock5://127.0.0.1:1081")
	cnt++
	sp, ok = pool.parent[cnt].ParentProxy.(*socksParent)
	if !ok {
		t.Fatal("sock5 alias parsed not as socksParent")
	}
	if sp.server != "127.0.0.1:1081" {
		t.Error("sock5 alias server address wrong, got:", sp.server)
	}

	parser.ParseProxy("ss://aes-256-cfb:foobar!@127.0.0.1:1080")
	cnt++
	_, ok = pool.parent[cnt].ParentProxy.(*shadowsocksParent)
	if !ok {
		t.Fatal("shadowsocks proxy parsed not as shadowsocksParent")
	}
}
