package main

import (
	"context"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	cases := map[string]float64{
		"512B/s":  512,
		"14KiB/s": 14 * 1024,
		"1GiB/s":  1 << 30,
		"15KiB":   15 * 1024,
		"50MB/s":  50e6,
		"100Mbit": 100e6 / 8,
		"1 Gbps":  1e9 / 8,
		"2.5Gbit": 2.5e9 / 8,
		"800Kb/s": 800e3 / 8,
		"8bit/s":  1,
	}
	for in, want := range cases {
		got, err := parseRate(in)
		if err != nil || math.Abs(got-want) > 1e-6 {
			t.Errorf("parseRate(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "fast", "10", "-5MB", "0MB", "10XB", "MB/s"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("parseRate(%q) should fail", bad)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pf.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExampleConfig(t *testing.T) {
	s, err := loadConfig("pf-simple.example.toml", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.forwards) != 3 || s.console == nil || s.console.addr != "127.0.0.1:18222" || s.console.password != "change-me" {
		t.Fatalf("unexpected settings: %+v console=%+v", s.forwards, s.console)
	}
	doris := s.forwards[1].stats
	if doris.name != "Doris MySQL" || doris.maxConns != 200 ||
		doris.totalRate != 1<<30 || doris.perConnRate != 15<<20 || doris.totalUp == nil || doris.totalDown == nil {
		t.Fatalf("doris forward: %+v", doris)
	}
	plain := s.forwards[2].stats
	if plain.name != "" || plain.totalUp != nil || plain.perConnRate != 14*1024 {
		t.Fatalf("unnamed forward: %+v", plain)
	}
	if http := s.forwards[0].stats; http.totalUp != nil || http.perConnRate != 0 || http.maxConns != 0 {
		t.Fatalf("HTTP forward should be unlimited: %+v", http)
	}
}

func TestConsoleOnlyConfigIsValid(t *testing.T) {
	s, err := loadConfig(writeConfig(t, "[console]\nlisten = \"20000\"\n"), "")
	if err != nil || s.console == nil || s.console.addr != "127.0.0.1:20000" || len(s.forwards) != 0 {
		t.Fatalf("console-only config: %+v %v", s, err)
	}
	if s.console.manage == nil {
		t.Fatal("config mode with a console must allow managing listeners")
	}
	fw, _ := parseForward("1@anything:1")
	if err := s.console.manage.check(fw); err != nil {
		t.Fatalf("no fences means no restriction: %v", err)
	}
	s, err = loadConfig(writeConfig(t, "[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"127.0.0.1:3\"\n"), "")
	if err != nil || s.console != nil {
		t.Fatalf("forward-only config: %+v %v", s, err)
	}
}

func TestManageNeedsWritableDirectory(t *testing.T) {
	path := writeConfig(t, "[console]\nlisten = \"20000\"\n")
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := loadConfig(path, ""); err == nil || !strings.Contains(err.Error(), "cannot create files") {
		t.Fatalf("read-only directory: %v", err)
	}
}

func TestConfigPasswordFallsBackToEnv(t *testing.T) {
	path := writeConfig(t, "[console]\nlisten = \"127.0.0.1:1\"\n[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"127.0.0.1:3\"\n")
	s, err := loadConfig(path, "from-env")
	if err != nil || s.console.password != "from-env" {
		t.Fatalf("console=%+v err=%v", s.console, err)
	}
}

func TestConfigErrors(t *testing.T) {
	fwd := "[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"127.0.0.1:3\"\n"
	cases := map[string]string{
		"unknown keys":                        fwd + "limit_up = \"1MB\"\n",
		"nothing to run":                      "# empty\n",
		"both listen and target are required": "[[forward]]\nlisten = \"127.0.0.1:2\"\n",
		"used twice":                          fwd + fwd,
		"total_speed":                         fwd + "total_speed = \"lots\"\n",
		"per_connection_max_speed":            fwd + "per_connection_max_speed = \"0B\"\n",
		"max_connections":                     fwd + "max_connections = -1\n",
		"invalid target address":              "[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"a:b:c\"\n",
		"[console] needs listen":              fwd + "[console]\npassword = \"x\"\n",
		"not a valid CIDR":                    "[console]\nlisten = \"1\"\nallow_target_hosts = [\"10.0.0.0/99\"]\n",
		"allow_bind_ports":                    "[console]\nlisten = \"1\"\nallow_bind_ports = \"9000-80\"\n",
	}
	for want, body := range cases {
		_, err := loadConfig(writeConfig(t, body), "")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: want error containing %q, got %v", body, want, err)
		}
	}
}

// startLimitedForwarder runs a forwarder whose listener has the given limits.
func startLimitedForwarder(t *testing.T, target string, configure func(*listenerStats)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	l := newListenerStats(0, ln.Addr().String(), target)
	configure(l)
	go acceptConnections(ctx, ln, l, halfCloseIdleTimeout)
	return ln.Addr().String()
}

// sinkServer discards everything and reports how many bytes arrived.
func sinkServer(t *testing.T) (string, chan int64) {
	got := make(chan int64, 16)
	addr := startServer(t, func(c *net.TCPConn) {
		n, _ := io.Copy(io.Discard, c)
		got <- n
	})
	return addr, got
}

func timeUpload(t *testing.T, addr string, size int) time.Duration {
	t.Helper()
	c := dial(t, addr)
	start := time.Now()
	if _, err := c.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	_, _ = io.Copy(io.Discard, c)
	return time.Since(start)
}

func TestPerConnectionSpeedLimit(t *testing.T) {
	target, got := sinkServer(t)
	addr := startLimitedForwarder(t, target, func(l *listenerStats) { l.perConnRate = 1 << 20 })
	elapsed := timeUpload(t, addr, 2<<20) // 2 MiB at 1 MiB/s
	if n := <-got; n != 2<<20 {
		t.Fatalf("upstream got %d bytes", n)
	}
	if elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatalf("2 MiB at 1 MiB/s took %v", elapsed)
	}
}

// Two pipes under a 1 MiB/s total, each allowed 4 MiB/s on its own, must
// share the total: together they need about 2s for 2 MiB.
func TestTotalSpeedLimitIsShared(t *testing.T) {
	target, got := sinkServer(t)
	addr := startLimitedForwarder(t, target, func(l *listenerStats) {
		l.totalRate = 1 << 20
		l.totalUp, l.totalDown = newLimiter(l.totalRate), newLimiter(l.totalRate)
		l.perConnRate = 4 << 20
	})
	start := time.Now()
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			timeUpload(t, addr, 1<<20)
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	elapsed := time.Since(start)
	if a, b := <-got, <-got; a+b != 2<<20 {
		t.Fatalf("upstream got %d + %d bytes", a, b)
	}
	if elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatalf("2 x 1 MiB under a 1 MiB/s total took %v", elapsed)
	}
}

func TestMaxConnections(t *testing.T) {
	target := startServer(t, func(c *net.TCPConn) { _, _ = io.Copy(c, c) })
	var stats *listenerStats
	addr := startLimitedForwarder(t, target, func(l *listenerStats) { l.maxConns = 1; stats = l })

	first := dial(t, addr)
	_, _ = first.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(first, buf); err != nil {
		t.Fatalf("first connection: %v", err)
	}

	second := dial(t, addr)
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := second.Read(buf); err == nil {
		t.Fatal("second connection should be refused")
	}
	if n := stats.rejected.Load(); n != 1 {
		t.Fatalf("rejected = %d", n)
	}

	// Closing the first frees its slot.
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for stats.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	third := dial(t, addr)
	_, _ = third.Write([]byte("ok"))
	if _, err := io.ReadFull(third, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("third connection after a slot freed: %q %v", buf, err)
	}
}

// With both limits set and the per-pipe cap the tighter one, two pipes get
// only 2 x 256 KiB/s even though the 1 MiB/s total would allow more.
func TestPerConnectionCapWinsUnderLooseTotal(t *testing.T) {
	target, got := sinkServer(t)
	addr := startLimitedForwarder(t, target, func(l *listenerStats) {
		l.totalRate = 1 << 20
		l.totalUp, l.totalDown = newLimiter(l.totalRate), newLimiter(l.totalRate)
		l.perConnRate = 256 << 10
	})
	start := time.Now()
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			timeUpload(t, addr, 512<<10) // 512 KiB each at 256 KiB/s: about 2s
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	elapsed := time.Since(start)
	if a, b := <-got, <-got; a+b != 1<<20 {
		t.Fatalf("upstream got %d + %d bytes", a, b)
	}
	if elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
		t.Fatalf("2 x 512 KiB at 256 KiB/s per pipe took %v; a loose 1 MiB/s total alone would take about 1s", elapsed)
	}
}
