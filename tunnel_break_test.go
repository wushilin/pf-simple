package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// A tunnelled connection is a chain of five parties and four links:
//
//	application -- pf-client connect == hub == pf-client serve -- target
//	            TCP                  WSS     WSS               TCP
//
// These tests break the chain at every point, in every way it can break,
// and check that the failure cascades: all five parties let go of the
// connection and both TCP sockets at the ends are really closed. Nothing is
// shortened: they run against the real timeouts, so they take about a
// minute and are skipped with -short.
//
// A party that sees the break itself lets go at once. Past it, the far side
// may still be sending, so it gets the half-close rule: the hub closes the
// connection once it has been idle for halfCloseIdleTimeout (30s). A link
// that goes silent without closing is first noticed after 30s without a
// ping, and then the same rule applies.

// flakyLink is a TCP forwarder in front of the hub that the test can cut or
// freeze, one connection at a time. TLS passes through it untouched.
type flakyLink struct {
	ln      net.Listener
	backend string

	mu    sync.Mutex
	pairs []*linkPair
}

// linkPair is one forwarded connection. dropUp discards what the client
// sends, dropDown what the hub sends: the sockets stay open and silent.
type linkPair struct {
	client, server   net.Conn
	dropUp, dropDown atomic.Bool
}

func newFlakyLink(t *testing.T, backend string) *flakyLink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &flakyLink{ln: ln, backend: backend}
	t.Cleanup(func() {
		ln.Close()
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, p := range l.pairs {
			p.cut()
		}
	})
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", backend)
			if err != nil {
				client.Close()
				continue
			}
			p := &linkPair{client: client, server: server}
			l.mu.Lock()
			l.pairs = append(l.pairs, p)
			l.mu.Unlock()
			go p.pump(server, client, &p.dropUp)
			go p.pump(client, server, &p.dropDown)
		}
	}()
	return l
}

func (p *linkPair) pump(dst, src net.Conn, drop *atomic.Bool) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !drop.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				p.cut()
				return
			}
		}
		if err != nil {
			// A silent direction swallows the close as it does the data:
			// the far end is left to notice the silence by itself.
			if !drop.Load() {
				p.cut()
			}
			return
		}
	}
}

// cut closes the connection abruptly: no WebSocket close, no TLS goodbye.
func (p *linkPair) cut() {
	p.client.Close()
	p.server.Close()
}

func (l *flakyLink) url() string { return "https://" + l.ln.Addr().String() }

// last is the newest connection: the leg of the connection just opened.
func (l *flakyLink) last() *linkPair {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pairs[len(l.pairs)-1]
}

// brokenEnv is one tunnelled connection, open and idle, ready to be broken.
type brokenEnv struct {
	t                      *testing.T
	hub                    *tunnelHub
	connectLink, serveLink *flakyLink
	app                    *net.TCPConn // the application on the connecting side
	target                 *net.TCPConn // the target's end of the connection
	stopConnect, stopServe context.CancelFunc
}

func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

func silence(p *linkPair, up, down bool) {
	p.dropUp.Store(up)
	p.dropDown.Store(down)
}

// closedByPeer reports whether the other end of c has closed its socket,
// not merely half-closed it: a write to a closed socket is answered with a
// reset, which the next write reports.
func closedByPeer(c *net.TCPConn) bool {
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := c.Write([]byte{0}); err != nil {
			return true
		}
	}
	return false
}

func TestRelayBrokenConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("runs against the real 30s timeouts")
	}
	// What the idle rule allows, plus slack for a loaded machine.
	idle := halfCloseIdleTimeout + 10*time.Second
	// A silent link is noticed after 30s, and then the idle rule applies.
	silent := 30*time.Second + idle
	const connect, serve = "connect", "serve"

	cases := []struct {
		name  string
		limit time.Duration
		// prompt lists the clients that see the break themselves and must
		// let go at once.
		prompt []string
		// The end that broke the connection has closed its own socket, and
		// a break that takes the tunnel down leaves nothing to check after.
		appGone, targetGone, tunnelGone bool
		// why is what the close line of pf-client connect, then of
		// pf-client serve, must say: the hop that broke, named the same way
		// at both ends.
		why [2]string
		brk func(e *brokenEnv)
	}{
		// 1. The application.
		{name: "the application closes its connection", why: [2]string{"the application closed its end, the target kept its own open, and the connection was idle for 30s", "the application closed its end, and the connection was idle for 30s"}, limit: idle, appGone: true,
			brk: func(e *brokenEnv) { e.app.Close() }},
		{name: "the application resets its connection", why: [2]string{"the application reset its connection to pf-client connect", "the application reset its connection to pf-client connect"}, limit: idle, prompt: []string{connect}, appGone: true,
			brk: func(e *brokenEnv) { reset(e.app) }},
		// 2. pf-client connect.
		{name: "pf-client connect stops", why: [2]string{"pf-client connect is stopping", "pf-client connect is stopping"}, limit: idle, prompt: []string{connect},
			brk: func(e *brokenEnv) { e.stopConnect() }},
		// 3. The link from pf-client connect to the hub.
		{name: "the connecting side's link is cut", why: [2]string{"the link between pf-client connect and the server was lost", "the link between pf-client connect and the server was lost"}, limit: idle, prompt: []string{connect},
			brk: func(e *brokenEnv) { e.connectLink.last().cut() }},
		{name: "the connecting side's link goes silent towards the hub", why: [2]string{"the link between pf-client connect and the server was silent for 30s", "the link between pf-client connect and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.connectLink.last(), true, false) }},
		{name: "the connecting side's link goes silent from the hub", why: [2]string{"the link between pf-client connect and the server was silent for 30s", "the link between pf-client connect and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.connectLink.last(), false, true) }},
		{name: "the connecting side's link goes silent both ways", why: [2]string{"the link between pf-client connect and the server was silent for 30s", "the link between pf-client connect and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.connectLink.last(), true, true) }},
		// 4. The hub.
		{name: "the hub resets the connection", why: [2]string{"the server reset the connection (reset from the console)", "the server reset the connection (reset from the console)"}, limit: idle, prompt: []string{connect, serve},
			brk: func(e *brokenEnv) {
				pipes.get(e.hub.snapshot().Words[0].Sessions[0].ID).interrupt("reset from the console")
			}},
		{name: "the hub resets the tunnel", why: [2]string{"the tunnel was closed on the server: reset from the console", "the tunnel was closed on the server: reset from the console"}, limit: idle, prompt: []string{connect, serve}, tunnelGone: true,
			brk: func(e *brokenEnv) {
				if err := e.hub.reset(e.hub.snapshot().Words[0].ID, false); err != nil {
					e.t.Error(err)
				}
			}},
		{name: "the hub drops off the network", why: [2]string{"the link between pf-client connect and the server was lost", "the link between pf-client serve and the server was lost"}, limit: idle, prompt: []string{connect, serve}, tunnelGone: true,
			brk: func(e *brokenEnv) {
				for _, l := range []*flakyLink{e.connectLink, e.serveLink} {
					l.mu.Lock()
					for _, p := range l.pairs {
						p.cut()
					}
					l.mu.Unlock()
				}
			}},
		// 5. The link from the hub to pf-client serve: the connection's own
		// leg, and the control channel the whole tunnel hangs on.
		{name: "the serving side's link is cut", why: [2]string{"the link between pf-client serve and the server was lost", "the link between pf-client serve and the server was lost"}, limit: idle, prompt: []string{serve},
			brk: func(e *brokenEnv) { e.serveLink.last().cut() }},
		{name: "the serving side's link goes silent towards the hub", why: [2]string{"the link between pf-client serve and the server was silent for 30s", "the link between pf-client serve and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.serveLink.last(), true, false) }},
		{name: "the serving side's link goes silent from the hub", why: [2]string{"the link between pf-client serve and the server was silent for 30s", "the link between pf-client serve and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.serveLink.last(), false, true) }},
		{name: "the serving side's link goes silent both ways", why: [2]string{"the link between pf-client serve and the server was silent for 30s", "the link between pf-client serve and the server was silent for 30s"}, limit: silent,
			brk: func(e *brokenEnv) { silence(e.serveLink.last(), true, true) }},
		{name: "the serving side's control channel is cut", why: [2]string{"the tunnel was closed on the server: the serving side disconnected", "the tunnel was closed on the server: the serving side disconnected"}, limit: idle, prompt: []string{connect, serve}, tunnelGone: true,
			brk: func(e *brokenEnv) {
				e.serveLink.mu.Lock()
				control := e.serveLink.pairs[0]
				e.serveLink.mu.Unlock()
				control.cut()
			}},
		// 6. pf-client serve.
		{name: "pf-client serve stops", why: [2]string{"the tunnel was closed on the server: the serving side disconnected", "pf-client serve is stopping"}, limit: idle, prompt: []string{connect, serve}, tunnelGone: true,
			brk: func(e *brokenEnv) { e.stopServe() }},
		// 7. The target.
		{name: "the target closes the connection", why: [2]string{"the target closed its end, and the connection was idle for 30s", "the target closed its end, the application kept its own open, and the connection was idle for 30s"}, limit: idle, targetGone: true,
			brk: func(e *brokenEnv) { e.target.Close() }},
		{name: "the target resets the connection", why: [2]string{"the target reset its connection to pf-client serve", "the target reset its connection to pf-client serve"}, limit: idle, prompt: []string{serve}, targetGone: true,
			brk: func(e *brokenEnv) { reset(e.target) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRelayFixture(t, "")
			backend := strings.TrimPrefix(f.srv.URL, "https://")
			e := &brokenEnv{t: t, hub: f.hub, connectLink: newFlakyLink(t, backend), serveLink: newFlakyLink(t, backend)}
			connectCtx, stopConnect := context.WithCancel(context.Background())
			serveCtx, stopServe := context.WithCancel(context.Background())
			defer stopConnect()
			defer stopServe()
			e.stopConnect, e.stopServe = stopConnect, stopServe

			// A target that answers once and then holds the connection
			// without a word, even after its peer half-closes: the worst
			// case, since nothing it does will end the connection.
			targetLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer targetLn.Close()
			accepted := make(chan *net.TCPConn, 1)
			go func() {
				c, err := targetLn.Accept()
				if err != nil {
					return
				}
				hello := make([]byte, 5)
				if _, err := io.ReadFull(c, hello); err == nil {
					_, _ = c.Write(hello)
				}
				accepted <- c.(*net.TCPConn)
				_, _ = io.Copy(io.Discard, c)
			}()

			// Each client reports the end of a connection in its log, with
			// how long it lasted, what it carried and why it ended.
			var reasons sync.Map
			ended := func(c *tunnel.Client) <-chan time.Time {
				ch := make(chan time.Time, 1)
				c.Logf = func(format string, args ...any) {
					if strings.HasPrefix(format, "connection %s closed after") {
						reasons.Store(c, fmt.Sprintf(format, args...))
						select {
						case ch <- time.Now():
						default:
						}
					}
				}
				return ch
			}
			newClient := func(l *flakyLink) *tunnel.Client {
				c, err := tunnel.NewClient(l.url(), testWord, f.tls)
				if err != nil {
					t.Fatal(err)
				}
				c.ServeToken, c.Name = testServeToken, "Test tunnel"
				return c
			}
			server, connector := newClient(e.serveLink), newClient(e.connectLink)
			serveEnded, connectEnded := ended(server), ended(connector)
			go server.Serve(serveCtx, targetLn.Addr().String())
			waitFor(t, "the word to be served", func() bool { return connector.Check(connectCtx) == nil })
			local, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go connector.Connect(connectCtx, local)

			app, err := net.Dial("tcp", local.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			e.app = app.(*net.TCPConn)
			_ = app.SetDeadline(time.Now().Add(20 * time.Second))
			hello := make([]byte, 5)
			if _, err := app.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(app, hello); err != nil {
				t.Fatalf("the connection never worked: %v", err)
			}
			_ = app.SetDeadline(time.Time{})
			e.target = <-accepted
			defer e.target.Close()
			sessions := f.hub.snapshot().Words[0].Sessions
			if len(sessions) != 1 {
				t.Fatalf("the hub holds %d connections before the break, want 1", len(sessions))
			}
			pipeID := sessions[0].ID

			start := time.Now()
			tc.brk(e)

			// The two clients.
			deadline := time.After(tc.limit)
			took := map[string]time.Duration{}
			for len(took) < 2 {
				select {
				case at := <-serveEnded:
					took[serve] = at.Sub(start)
				case at := <-connectEnded:
					took[connect] = at.Sub(start)
				case <-deadline:
					t.Fatalf("after %s the connection is still held; let go so far: %v", tc.limit, took)
				}
			}
			// The hub: the connection is gone from the tunnel and from the
			// registry of live pipes.
			hubHolds := func() bool {
				if pipes.get(pipeID) != nil {
					return true
				}
				words := f.hub.snapshot().Words
				return len(words) > 0 && words[0].Conns != 0
			}
			for time.Since(start) < tc.limit && hubHolds() {
				time.Sleep(20 * time.Millisecond)
			}
			hubTook := time.Since(start)
			if hubHolds() {
				t.Fatalf("after %s the hub still holds the connection", tc.limit)
			}
			t.Logf("let go after: pf-client connect %s, hub %s, pf-client serve %s",
				took[connect].Round(100*time.Millisecond), hubTook.Round(100*time.Millisecond), took[serve].Round(100*time.Millisecond))
			for i, name := range []string{connect, serve} {
				line, _ := reasons.Load(map[string]*tunnel.Client{connect: connector, serve: server}[name])
				t.Logf("  %-7s %v", name, line)
				if text, _ := line.(string); !strings.Contains(text, "; "+tc.why[i]) {
					t.Errorf("pf-client %s gave the wrong reason: want %q in %v", name, tc.why[i], line)
				}
				// 5 bytes went each way before the break.
				if text, _ := line.(string); !strings.Contains(text, "app->target 5 B, target->app 5 B; ") {
					t.Errorf("pf-client %s logged the wrong byte counts: %v", name, line)
				}
			}
			for _, side := range tc.prompt {
				if took[side] > 5*time.Second {
					t.Errorf("pf-client %s saw the break itself but took %s to let go", side, took[side])
				}
			}
			// The two ends: each client closed its TCP socket for real.
			if !tc.appGone && !closedByPeer(e.app) {
				t.Error("pf-client connect let go, but the application's socket is still open")
			}
			if !tc.targetGone && !closedByPeer(e.target) {
				t.Error("pf-client serve let go, but the target's socket is still open")
			}
			// Only this connection ended; the tunnel is unharmed.
			if !tc.tunnelGone {
				if err := connector.Check(connectCtx); err != nil && connectCtx.Err() == nil {
					t.Errorf("the tunnel did not survive a broken connection: %v", err)
				}
				if n := len(f.hub.snapshot().Words); n != 1 || !f.hub.snapshot().Words[0].Live {
					t.Errorf("the tunnel is no longer live after a broken connection")
				}
			}
		})
	}
}
