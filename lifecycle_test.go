package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The server's connection lifecycle, from a review: each of these held
// connections or goroutines, or stalled, before its fix.

// A console client that sends its headers and then nothing, or never
// reads, is let go after the console's timeouts.
func TestConsoleSlowRequestsAreBounded(t *testing.T) {
	defer func(r, w time.Duration) { consoleReadTimeout, consoleWriteTimeout = r, w }(consoleReadTimeout, consoleWriteTimeout)
	consoleReadTimeout, consoleWriteTimeout = time.Second, 2*time.Second
	mgr := newManager(nil, nil, halfCloseIdleTimeout)
	cs := newConsoleServer("", "secret", mgr)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cs.serve(ctx, ln)
	var conns []net.Conn
	for _, req := range []string{
		"POST /pf/api/login HTTP/1.1\r\nHost: x\r\nX-PF-Console: 1\r\nContent-Length: 10\r\n\r\n",
		"GET /pf/api/health HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n",
	} {
		for i := 0; i < 10; i++ {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, _ = c.Write([]byte(req))
			conns = append(conns, c)
		}
	}
	time.Sleep(3 * time.Second)
	held := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := c.Read(make([]byte, 4096))
		for err == nil { // an answer, then the close
			_, err = c.Read(make([]byte, 4096))
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			held++
		}
	}
	if held != 0 {
		t.Errorf("%d of %d slow requests still held after the read timeout", held, len(conns))
	}
}

// A forwarding listener that fails to accept, here for want of file
// descriptors, keeps going once it can.
func TestForwardSurvivesAcceptErrors(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc")
	}
	logs := &syncBuffer{} // the server's goroutines log into it while the test reads
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)
	target := echoTarget(t)
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	free := tmp.Addr().String()
	tmp.Close()
	fw, err := parseForward(free + "@" + target)
	if err != nil {
		t.Fatal(err)
	}
	mgr := newManager([]forwarding{fw}, nil, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mgr.startAll(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.shutdown()
	addr := mgr.list[0].ln.Addr().String()
	echo := func() error {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		_, err = c.Read(make([]byte, 4))
		return err
	}
	if err := echo(); err != nil {
		t.Fatalf("before: %v", err)
	}
	var lim syscall.Rlimit
	_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	ents, _ := os.ReadDir("/proc/self/fd")
	low := lim
	low.Cur = uint64(len(ents) + 64)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Skipf("cannot lower the descriptor limit: %v", err)
	}
	var hogs []*os.File
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			break
		}
		hogs = append(hogs, f)
	}
	hogs[0].Close() // one descriptor left: the client's socket
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		time.Sleep(500 * time.Millisecond) // the forwarder's accept fails
		c.Close()
	}
	for _, f := range hogs[1:] {
		f.Close()
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	if !strings.Contains(logs.String(), "trying again") {
		t.Errorf("no failed accept was retried; log: %s", logs.String())
	}
	var last error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if last = echo(); last == nil {
			return
		}
	}
	t.Fatalf("the forwarder stopped accepting after descriptors ran out: %v", last)
}

// A control channel the hub can no longer write to ends its tunnel, and
// the connection that found out hears why, at once.
func TestControlWriteFailureDropsTunnel(t *testing.T) {
	f := newRelayFixture(t, "")
	f.fakeServe(t)
	var tun *relayTunnel
	f.hub.mu.Lock()
	for _, x := range f.hub.tunnels {
		tun = x
	}
	f.hub.mu.Unlock()
	tun.ctl.ExpireWrites() // as after a write that timed out
	c := f.client(t, testWord, "")
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection went through a control channel that cannot be written to")
	}
	waitFor(t, "the tunnel to be dropped", func() bool {
		f.hub.mu.Lock()
		defer f.hub.mu.Unlock()
		return len(f.hub.tunnels) == 0
	})
}

// drop is bounded, also behind a write to a control channel whose serving
// side has stopped reading.
func TestDropIsBoundedBehindAStuckWrite(t *testing.T) {
	f := newRelayFixture(t, "")
	// A serving side that registers and then never reads its control
	// channel again.
	h := http.Header{}
	h.Set(tunnel.HeaderWord, testWord)
	h.Set(tunnel.HeaderServe, testServeToken)
	h.Set(tunnel.HeaderName, "Stuck")
	h.Set(tunnel.HeaderTarget, "stuck")
	h.Set(tunnel.HeaderProto, "0-2")
	ctl, err := tunnel.Dial(context.Background(), f.srv.URL+tunnel.Path+"/serve", h, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	var tun *relayTunnel
	f.hub.mu.Lock()
	for _, x := range f.hub.tunnels {
		tun = x
	}
	f.hub.mu.Unlock()
	stuck := make(chan struct{})
	go func() { // fill the channel until a write blocks
		frame := make([]byte, 4000)
		for tun.ctl.WriteFrame(tunnel.OpText, frame) == nil {
			tunnelCtlWrites.Add(1)
		}
		close(stuck)
	}()
	// Until the writer is stuck: no write has finished for a while.
	waitFor(t, "a write to block", func() bool {
		select {
		case <-stuck:
			t.Fatal("the writes failed instead of blocking")
		default:
		}
		before := tunnelCtlWrites.Load()
		time.Sleep(300 * time.Millisecond)
		return tunnelCtlWrites.Load() == before
	})
	start := time.Now()
	f.hub.drop(tun, "reset from the console")
	if took := time.Since(start); took > 7*time.Second {
		t.Errorf("drop took %s behind a stuck write", took.Round(100*time.Millisecond))
	}
	<-stuck
}

var tunnelCtlWrites atomic.Int64

// Ending a tunnel resets its connections at once, not one after another,
// also when their peers do not read.
func TestDropResetsConnectionsTogether(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	const n = 6
	for i := 0; i < n; i++ {
		h := http.Header{}
		h.Set(tunnel.HeaderWord, testWord)
		c, err := tunnel.Dial(context.Background(), f.srv.URL+tunnel.Path+"/connect", h, f.tls)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() }) // never read
		leg := fs.accept(fs.nextOpen(), "")
		leg.SetTimeouts(0, 0)
		go func() {
			chunk := make([]byte, 64<<10)
			for leg.WriteFrame(tunnel.OpBinary, chunk) == nil {
			}
		}()
	}
	// Until the hub's writes to the connecting sides have stalled.
	var last uint64
	for stable := 0; stable < 10; {
		time.Sleep(200 * time.Millisecond)
		var sum uint64
		live, _ := pipes.list(0)
		for _, p := range live {
			sum += p.down.written.Load()
		}
		if sum == last && sum > 0 && len(live) == n {
			stable++
		} else {
			stable = 0
		}
		last = sum
	}
	start := time.Now()
	f.hub.closeAll()
	if took := time.Since(start); took > 6*time.Second {
		t.Errorf("closing a tunnel with %d stalled connections took %s", n, took.Round(100*time.Millisecond))
	}
}
