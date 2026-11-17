package main

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/quictun"
	"github.com/wushilin/pf-simple/internal/tunnel"
	"github.com/wushilin/pf-simple/pfrelay"
)

// The cross-transport matrix (docs/PROTOCOL.md §13.13): every case below,
// on every pairing of a connecting side and a serving side, through one
// hub. A connection's two legs may be on different transports, and must
// fail the same way whatever they are: each side reports the reason in the
// table, and the hub holds nothing for the connection afterwards.

// sideKind is how one side reaches the hub.
type sideKind int

const (
	wsProto1 sideKind = iota // WebSocket, protocol 1: no reuse
	wsFresh                  // WebSocket, protocol 2, on a leg that is new
	wsReused                 // WebSocket, protocol 2, on a leg carried before
	overQUIC
)

func (k sideKind) String() string {
	return [...]string{"ws1", "ws2 fresh", "ws2 reused", "quic"}[k]
}

// udpLink forwards UDP to the hub's QUIC listener, and can go silent, as a
// network that drops everything does: QUIC has no reset to notice.
type udpLink struct {
	pc    net.PacketConn
	hub   string
	quiet atomic.Bool
	mu    sync.Mutex
	flows map[string]net.Conn
}

func newUDPLink(t *testing.T, hub string) *udpLink {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &udpLink{pc: pc, hub: hub, flows: map[string]net.Conn{}}
	t.Cleanup(func() {
		pc.Close()
		l.mu.Lock()
		for _, f := range l.flows {
			f.Close()
		}
		l.mu.Unlock()
	})
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if l.quiet.Load() {
				continue
			}
			l.mu.Lock()
			up := l.flows[from.String()]
			if up == nil {
				if up, err = net.Dial("udp", hub); err != nil {
					l.mu.Unlock()
					continue
				}
				l.flows[from.String()] = up
				go func(up net.Conn, to net.Addr) {
					b := make([]byte, 64<<10)
					for {
						n, err := up.Read(b)
						if err != nil {
							return
						}
						if !l.quiet.Load() {
							_, _ = pc.WriteTo(b[:n], to)
						}
					}
				}(up, from)
			}
			l.mu.Unlock()
			_, _ = up.Write(buf[:n])
		}
	}()
	return l
}

func (l *udpLink) port() int { return l.pc.LocalAddr().(*net.UDPAddr).Port }

// crossEnv is one pairing, with one connection open between its sides.
type crossEnv struct {
	t               *testing.T
	f               *relayFixture
	ctx             context.Context
	server, dialer  *pfrelay.Client
	listener        *pfrelay.Listener
	q               *quicHub
	app, target     *pfrelay.Conn // the connecting side's and the serving side's end
	cutServe        func()        // the serving side's link goes dead
	cutConnect      func()        // the connecting side's link goes dead
	serveKind, dial sideKind
}

// crossPair sets up a hub and the two sides of one pairing. The serving
// side listens; reused takes one connection through first, so that the
// next is carried on a reused leg.
func crossPair(t *testing.T, dial, serve sideKind, clientToken string) *crossEnv {
	t.Helper()
	f := newRelayFixture(t, "")
	f.hub.idle = 700 * time.Millisecond // the half-close idle rule (§8.2), shortened
	q := f.withQUIC(t)
	_, hubPort, _ := net.SplitHostPort(q.pc.LocalAddr().String())
	hubUDP := "127.0.0.1:" + hubPort
	serveUDP, connectUDP := newUDPLink(t, hubUDP), newUDPLink(t, hubUDP)
	q.advertiseFor = func(op string) int {
		if op == "serve" {
			return serveUDP.port()
		}
		return connectUDP.port()
	}
	hubTCP := strings.TrimPrefix(f.srv.URL, "https://")
	serveTCP, connectTCP := newFlakyLink(t, hubTCP), newFlakyLink(t, hubTCP)
	cutAll := func(l *flakyLink) {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, p := range l.pairs {
			p.cut()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := &crossEnv{t: t, f: f, q: q, ctx: ctx, serveKind: serve, dial: dial}

	mk := func(k sideKind, link *flakyLink, token string) *pfrelay.Client {
		var c *pfrelay.Client
		if k == overQUIC {
			c = f.quicClient(t, testWord, token)
		} else {
			var err error
			if c, err = pfrelay.NewClient(link.url(), testWord, f.tls); err != nil {
				t.Fatal(err)
			}
			c.ServeToken, c.Name, c.Logf = token, "Test tunnel", func(string, ...any) {}
			t.Cleanup(func() { c.Close() })
			if k == wsProto1 {
				c.MaxProto = 1
			}
		}
		c.ClientToken = clientToken
		return c
	}
	e.server, e.dialer = mk(serve, serveTCP, testServeToken), mk(dial, connectTCP, "")
	e.cutServe, e.cutConnect = func() { cutAll(serveTCP) }, func() { cutAll(connectTCP) }
	if serve == overQUIC {
		e.cutServe = func() { serveUDP.quiet.Store(true) }
	}
	if dial == overQUIC {
		e.cutConnect = func() { connectUDP.quiet.Store(true) }
	}
	return e
}

// listen starts the serving side's listener and waits until the tunnel can
// be reached.
func (e *crossEnv) listen() {
	e.t.Helper()
	l, err := e.server.Listen(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { l.Close() })
	e.listener = l
	waitFor(e.t, "the tunnel to be up", func() bool { return e.dialer.Check(e.ctx) == nil })
	if e.serveKind == wsReused {
		e.open()
		echoBoth(e.t, e.app, e.target)
		waitFor(e.t, "a leg in the pool", func() bool { return len(e.f.wordSnap(e.t).Idle) == 1 })
	}
}

// open opens one connection: the connecting side dials, the serving side
// accepts.
func (e *crossEnv) open() {
	e.t.Helper()
	app, err := e.dialer.Dial(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { app.Close() })
	accepted := make(chan *pfrelay.Conn, 1)
	go func() {
		c, err := e.listener.AcceptConn()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case e.target = <-accepted:
		e.t.Cleanup(func() { e.target.Close() })
	case <-time.After(10 * time.Second):
		e.t.Fatal("the serving side accepted nothing")
	}
	e.app = app
	// A byte each way: the connection is carried end to end before a case
	// breaks it, not still being set up at the hub.
	b := make([]byte, 1)
	for _, p := range [][2]*pfrelay.Conn{{app, e.target}, {e.target, app}} {
		_ = p[1].SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := p[0].Write([]byte{1}); err != nil {
			e.t.Fatal(err)
		}
		if _, err := io.ReadFull(p[1], b); err != nil {
			e.t.Fatal(err)
		}
		_ = p[1].SetReadDeadline(time.Time{})
	}
}

// echoBoth runs a clean connection to its end: a line each way, and a
// half-close from each side.
func echoBoth(t *testing.T, app, target *pfrelay.Conn) {
	t.Helper()
	go func() {
		b, _ := io.ReadAll(target)
		_, _ = target.Write(b)
		_ = target.CloseWrite()
	}()
	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = app.CloseWrite()
	_ = app.SetReadDeadline(time.Now().Add(10 * time.Second))
	if b, err := io.ReadAll(app); err != nil || string(b) != "hello" {
		t.Fatalf("echo %q, %v", b, err)
	}
	app.Close()
	target.Close()
}

// endOf reads c until it ends, and returns why: "" for a clean end.
func endOf(c *pfrelay.Conn, within time.Duration) string {
	_ = c.SetReadDeadline(time.Now().Add(within))
	_, err := io.Copy(io.Discard, c)
	// A failure is passed on as a half-close first, and its reason follows
	// when the whole connection ends (§8.3): within the idle rule.
	for deadline := time.Now().Add(1500 * time.Millisecond); err == nil && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		err = c.Err()
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// lateFailure half-closes failing, waits until other has read that
// half-close, and then fails failing with reason. With thenHalfClose,
// other then half-closes as well, once the hub has the reason: an eof that
// reaches the hub first finishes the connection cleanly, as it may.
func lateFailure(e *crossEnv, failing, other *pfrelay.Conn, reason string, thenHalfClose bool) {
	e.t.Helper()
	_ = failing.CloseWrite()
	_ = other.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadAll(other)
	_ = other.SetReadDeadline(time.Time{})
	failing.Fail(reason)
	if thenHalfClose {
		waitFor(e.t, "the hub to read the late err", func() bool { return hubHeard(reason) || other.Err() != nil })
		_ = other.CloseWrite()
	}
}

// hubHeard reports whether a leg of a pipe at the hub failed with reason
// after its half-close.
func hubHeard(reason string) bool {
	live, _ := pipes.list(1 << 10)
	for _, p := range live {
		for _, c := range []net.Conn{p.client, p.upstream} {
			var s *tunnel.Stream
			switch x := c.(type) {
			case *tunnel.Stream:
				s = x
			case *reusableUpstream:
				s = x.Stream
			}
			if s != nil && s.GoneReason() == reason {
				return true
			}
		}
	}
	return false
}

// crossCase is one way for a connection to end.
type crossCase struct {
	name string
	// run ends the connection; app and target are what each side must
	// report, as substrings, "a|b" for either.
	run         func(e *crossEnv) (app, target string)
	app, target string
}

func ptr(s string) *string { return &s }

func f(e *crossEnv) *relayFixture { return e.f }

func matches(got, want string) bool {
	for _, w := range strings.Split(want, "|") {
		if (w == "" && got == "") || (w != "" && strings.Contains(got, w)) {
			return true
		}
	}
	return false
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// crossCases are the ways a connection can end (§13.13). Each run ends the
// connection and returns what the connecting and the serving side report.
//
// app and target are what each side must report, as substrings, "a|b" for
// either, "" for a clean end. onReuse replaces target where the serving
// side is on a leg offered reuse: its connection ends with the hub's eof
// and idle, and does not hear the other side's reason (§12.5). keepsLeg
// says whether such a leg goes back to the pool.
var crossCases = []struct {
	name        string
	forward     string // serve this target with the forwarder, instead of listening
	app, target string
	onReuse     *string
	keepsLeg    bool
	run         func(e *crossEnv) (app, target string)
}{
	{name: "clean echo", keepsLeg: true, run: func(e *crossEnv) (string, string) {
		e.open()
		echoBoth(e.t, e.app, e.target)
		return errText(e.app.Err()), errText(e.target.Err())
	}},
	{name: "wrong client token", app: "access denied", keepsLeg: true, run: func(e *crossEnv) (string, string) {
		e.dialer.ClientToken = "wrong-client-token"
		_, err := e.dialer.Dial(e.ctx)
		return errText(err), ""
	}},
	{name: "target unreachable", forward: "127.0.0.1:1", app: "the serving side could not reach its target", run: func(e *crossEnv) (string, string) {
		app, err := e.dialer.Dial(e.ctx)
		if err != nil {
			return err.Error(), ""
		}
		defer app.Close()
		return endOf(app, 10*time.Second), ""
	}},
	{name: "target resets", app: "the target reset its connection", run: func(e *crossEnv) (string, string) {
		e.open()
		e.target.Fail("the target reset its connection")
		return endOf(e.app, 10*time.Second), errText(e.target.Err())
	}},
	{name: "application resets", target: "the application reset its connection", onReuse: ptr(""), keepsLeg: true, run: func(e *crossEnv) (string, string) {
		e.open()
		e.app.Fail("the application reset its connection")
		return errText(e.app.Err()), endOf(e.target, 10*time.Second)
	}},
	{name: "serving link lost", app: "the tunnel was closed on the server: the serving side disconnected",
		target: "unexpected EOF|no recent network activity", run: func(e *crossEnv) (string, string) {
			e.open()
			e.cutServe()
			return endOf(e.app, 10*time.Second), endOf(e.target, 10*time.Second)
		}},
	{name: "connecting link lost", app: "unexpected EOF|no recent network activity",
		target: "the link between pf-client connect and the server was", onReuse: ptr(""), keepsLeg: true, run: func(e *crossEnv) (string, string) {
			e.open()
			e.cutConnect()
			return endOf(e.app, 10*time.Second), endOf(e.target, 10*time.Second)
		}},
	{name: "failure after a half-close", app: "a late failure", run: func(e *crossEnv) (string, string) {
		e.open()
		_ = e.app.CloseWrite()
		_ = e.target.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.ReadAll(e.target)
		e.target.Fail("a late failure")
		return endOf(e.app, 10*time.Second), errText(e.target.Err())
	}},
	// A side that fails after its own half-close: the err follows its eof
	// (§8.3, §13.5), and must not be lost behind it, whether the other
	// side then half-closes too or the connection falls idle.
	{name: "target fails after its own half-close", app: "a late failure of the target", run: func(e *crossEnv) (string, string) {
		e.open()
		lateFailure(e, e.target, e.app, "a late failure of the target", false)
		return endOf(e.app, 10*time.Second), errText(e.target.Err())
	}},
	{name: "target fails after its own half-close, then the application half-closes", app: "a late failure of the target", run: func(e *crossEnv) (string, string) {
		e.open()
		lateFailure(e, e.target, e.app, "a late failure of the target", true)
		return endOf(e.app, 10*time.Second), errText(e.target.Err())
	}},
	{name: "application fails after its own half-close", target: "a late failure of the application", onReuse: ptr(""), keepsLeg: true, run: func(e *crossEnv) (string, string) {
		e.open()
		lateFailure(e, e.app, e.target, "a late failure of the application", false)
		return errText(e.app.Err()), endOf(e.target, 10*time.Second)
	}},
	{name: "application fails after its own half-close, then the target half-closes", target: "a late failure of the application", onReuse: ptr(""), keepsLeg: true, run: func(e *crossEnv) (string, string) {
		e.open()
		lateFailure(e, e.app, e.target, "a late failure of the application", true)
		return errText(e.app.Err()), endOf(e.target, 10*time.Second)
	}},
	{name: "half-closed and silent", app: "the application closed its end, the target kept its own open, and the connection was idle",
		target: "the application closed its end, and the connection was idle", onReuse: ptr(""), keepsLeg: true, run: func(e *crossEnv) (string, string) {
			e.open()
			_ = e.app.CloseWrite()
			_ = e.target.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.ReadAll(e.target)
			// The serving side first: on a reused leg it must close its
			// end within the hub's wait for it (§12.5).
			target := endOf(e.target, 10*time.Second)
			e.target.Close()
			return endOf(e.app, 10*time.Second), target
		}},
	{name: "registration ends", app: "the tunnel was closed on the server: the serving side disconnected",
		target: "the tunnel was closed on the server: the serving side disconnected", run: func(e *crossEnv) (string, string) {
			e.open()
			e.listener.Close()
			return endOf(e.app, 10*time.Second), endOf(e.target, 10*time.Second)
		}},
}

func TestCrossTransport(t *testing.T) {
	defer func(i, k time.Duration) { quictun.IdleTimeout, quictun.KeepAlive = i, k }(quictun.IdleTimeout, quictun.KeepAlive)
	quictun.IdleTimeout, quictun.KeepAlive = 1500*time.Millisecond, 300*time.Millisecond // a dead QUIC link in 1.5s
	for _, dial := range []sideKind{wsFresh, overQUIC} {
		for _, serve := range []sideKind{wsProto1, wsFresh, wsReused, overQUIC} {
			for _, c := range crossCases {
				t.Run(dial.String()+" to "+serve.String()+"/"+c.name, func(t *testing.T) {
					e := crossPair(t, dial, serve, "open-sesame")
					if c.forward != "" {
						go func() { _ = e.server.Serve(e.ctx, c.forward) }()
						waitFor(t, "the tunnel to be up", func() bool { return e.dialer.Check(e.ctx) == nil })
					} else {
						e.listen()
					}
					app, target := c.run(e)
					// Each side closes its end once its connection has ended,
					// as an application does.
					for _, conn := range []*pfrelay.Conn{e.app, e.target} {
						if conn != nil {
							conn.Close()
						}
					}
					wantTarget := c.target
					reuse := serve == wsFresh || serve == wsReused
					if reuse && c.onReuse != nil {
						wantTarget = *c.onReuse
					}
					if !matches(app, c.app) {
						t.Errorf("the connecting side reported %q, want %q", app, c.app)
					}
					if !matches(target, wantTarget) {
						t.Errorf("the serving side reported %q, want %q", target, wantTarget)
					}
					// Nothing is left of the connection at the hub.
					waitFor(t, "the hub to let go of the connection", func() bool {
						for _, w := range f(e).hub.snapshot().Words {
							if w.Conns != 0 || len(w.Sessions) != 0 {
								return false
							}
						}
						return e.q.total.Load() <= 1 // at most the serve stream
					})
					if serve == wsReused && c.forward == "" {
						if c.keepsLeg {
							waitFor(t, "the reused leg back in the pool", func() bool { return len(e.f.wordSnap(t).Idle) >= 1 })
						}
					}
				})
			}
		}
	}
}
