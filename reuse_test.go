package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
	"github.com/wushilin/pf-simple/pfrelay"
)

// Tunnel protocol 2: reusing the serving side's accept legs
// (docs/PROTOCOL.md §12).

// wordSnap is the console's view of the one word served.
func (f *relayFixture) wordSnap(t *testing.T) relayWordSnapshot {
	t.Helper()
	words := f.hub.snapshot().Words
	if len(words) != 1 {
		t.Fatalf("%d words", len(words))
	}
	return words[0]
}

// echoOnce sends payload over a new connection and checks it comes back.
func echoOnce(t *testing.T, c *pfrelay.Client, payload string) {
	t.Helper()
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := echoOver(conn, []byte(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestReuseSequentialConnections(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.goServeWith(t, ctx, echoTarget(t), nil)
	c := f.client(t, testWord, "")
	for i := 0; i < 6; i++ {
		echoOnce(t, c, "hello")
		// The leg goes back to the pool a moment after the finish.
		waitFor(t, "an idle leg", func() bool { return len(f.wordSnap(t).Idle) == 1 })
	}
	w := f.wordSnap(t)
	if !w.Reuse || w.Reused != 5 || w.Proto != 2 {
		t.Errorf("reuse %v, reused %d, protocol %d; want true, 5, 2", w.Reuse, w.Reused, w.Proto)
	}
	if w.Idle[0].Carried != 6 {
		t.Errorf("the idle leg carried %d connections, want 6", w.Idle[0].Carried)
	}
}

// goServeWith serves testWord to target with a Go client that set may
// change first.
func (f *relayFixture) goServeWith(t *testing.T, ctx context.Context, target string, set func(*pfrelay.Client)) {
	t.Helper()
	s := f.client(t, testWord, testServeToken)
	if set != nil {
		set(s)
	}
	go func() { _ = s.Serve(ctx, target) }()
	c := f.client(t, testWord, "")
	waitFor(t, "the word to be served", func() bool { return c.Check(ctx) == nil })
}

// Every combination of protocols works; only 2 with 2 reuses legs.
func TestReuseProtocolMatrix(t *testing.T) {
	for _, tc := range []struct {
		name          string
		hub           int // the hub's newest protocol; 0 = like a hub from before 0.14
		serve, dial   int // pfrelay.Client.MaxProto
		reuse         bool
		sessionIssued bool
	}{
		{"hub 2, serve 2", 2, 0, 0, true, true},
		{"hub 2, serve 2, connect 1", 2, 0, 1, true, true},
		{"hub 2, serve 2, connect 0", 2, 0, -1, true, true},
		{"hub 2, serve 1", 2, 1, 0, false, false},
		{"hub 2, serve 0", 2, -1, 0, false, false},
		{"hub 1, serve 2", 1, 0, 0, false, false},
		{"hub 0, serve 2", 0, 0, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t, "")
			f.hub.mu.Lock()
			switch tc.hub {
			case 0:
				f.hub.silent = true
			case 1:
				f.hub.maxProto = 1
			}
			f.hub.mu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.goServeWith(t, ctx, echoTarget(t), func(c *pfrelay.Client) { c.MaxProto = tc.serve })
			c := f.client(t, testWord, "")
			c.MaxProto = tc.dial
			for i := 0; i < 3; i++ {
				echoOnce(t, c, strings.Repeat("x", 1000))
			}
			time.Sleep(100 * time.Millisecond)
			w := f.wordSnap(t)
			if got := w.Reused > 0; got != tc.reuse {
				t.Errorf("reused %d connections; want reuse %v", w.Reused, tc.reuse)
			}
			f.hub.mu.Lock()
			var issued bool
			for _, tn := range f.hub.tunnels {
				issued = tn.session != nil
			}
			f.hub.mu.Unlock()
			if issued != tc.sessionIssued {
				t.Errorf("session issued %v, want %v", issued, tc.sessionIssued)
			}
		})
	}
}

// fakeServe is a serving side driven by hand, to check what the hub does
// with a peer that does not follow the script.
type fakeServe struct {
	t       *testing.T
	f       *relayFixture
	ctl     *tunnel.Conn
	session string
	opens   chan string
}

func (f *relayFixture) fakeServe(t *testing.T) *fakeServe {
	t.Helper()
	h := http.Header{}
	h.Set(tunnel.HeaderWord, testWord)
	h.Set(tunnel.HeaderServe, testServeToken)
	h.Set(tunnel.HeaderName, "Fake")
	h.Set(tunnel.HeaderTarget, "fake")
	h.Set(tunnel.HeaderProto, "0-2")
	ctl, err := tunnel.Dial(context.Background(), f.srv.URL+tunnel.Path+"/serve", h, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	fs := &fakeServe{t: t, f: f, ctl: ctl, session: ctl.Header.Get(tunnel.HeaderSession), opens: make(chan string, 16)}
	if len(fs.session) != 32 {
		t.Fatalf("no session on the serve 101: %q", fs.session)
	}
	go func() {
		for {
			op, payload, err := ctl.Next(tunnel.MaxSmallFrame)
			if err != nil {
				close(fs.opens)
				return
			}
			var msg tunnel.ControlMessage
			if op == tunnel.OpText && json.Unmarshal(payload, &msg) == nil && msg.Open != "" {
				fs.opens <- msg.Open
			}
		}
	}()
	return fs
}

// accept brings a leg for id; session "" sends none.
func (fs *fakeServe) accept(id, session string) *tunnel.Conn {
	fs.t.Helper()
	h := http.Header{}
	h.Set(tunnel.HeaderWord, testWord)
	h.Set(tunnel.HeaderConn, id)
	h.Set(tunnel.HeaderProto, "0-2")
	if session != "" {
		h.Set(tunnel.HeaderSession, session)
	}
	ws, err := tunnel.Dial(context.Background(), fs.f.srv.URL+tunnel.Path+"/accept", h, fs.f.tls)
	if err != nil {
		fs.t.Fatal(err)
	}
	fs.t.Cleanup(func() { ws.Close() })
	return ws
}

func (fs *fakeServe) nextOpen() string {
	fs.t.Helper()
	select {
	case id := <-fs.opens:
		return id
	case <-time.After(10 * time.Second):
		fs.t.Fatal("no open message")
	}
	return ""
}

// echoLeg answers one connection on leg as an echo target would: data back,
// then a half-close after the far end's, and then the hub's verdict.
func echoLeg(t *testing.T, leg *tunnel.Conn) (verdict string) {
	t.Helper()
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			return "closed"
		}
		switch {
		case op == tunnel.OpBinary:
			_ = leg.WriteFrame(tunnel.OpBinary, payload)
		case op == tunnel.OpText && string(payload) == "eof":
			_ = leg.WriteFrame(tunnel.OpText, []byte("eof"))
		case op == tunnel.OpText:
			return string(payload)
		}
	}
}

// dialEcho opens a connection, sends a line, half-closes and returns the
// connection for reading the answer.
func dialEcho(t *testing.T, c *pfrelay.Client) *pfrelay.Conn {
	t.Helper()
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWrite()
	return conn
}

func readAll(t *testing.T, conn *pfrelay.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read %q: %v", b, err)
	}
	return string(b)
}

// Only the registered serving side can offer a leg for reuse. The
// connecting side learns the connection id too, and may answer accept for
// its own connection, but it gets a plain leg.
func TestReuseNeedsTheSession(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")

	for _, tc := range []struct{ name, session string }{
		{"no session", ""},
		{"a wrong session", strings.Repeat("ab", 16)},
		{"not hex", strings.Repeat("z", 32)},
	} {
		conn := dialEcho(t, c)
		id := fs.nextOpen()
		if id != conn.ID().String() {
			t.Fatalf("open %q for connection %s", id, conn.ID())
		}
		leg := fs.accept(id, tc.session)
		if v := leg.Header.Get(tunnel.HeaderKeepAlive); v != "" {
			t.Errorf("%s: offered reuse: %q", tc.name, v)
		}
		go echoLeg(t, leg)
		if got := readAll(t, conn); got != "hello" {
			t.Errorf("%s: read %q", tc.name, got)
		}
	}
	conn := dialEcho(t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	if v := leg.Header.Get(tunnel.HeaderKeepAlive); v != "60" {
		t.Errorf("with the session, the offer is %q, want 60", v)
	}
	go echoLeg(t, leg)
	if got := readAll(t, conn); got != "hello" {
		t.Errorf("read %q", got)
	}
}

// keptLeg runs one connection through the fake serving side on an offered
// leg, and keeps the leg.
func (fs *fakeServe) keptLeg(c *pfrelay.Client) *tunnel.Conn {
	fs.t.Helper()
	conn := dialEcho(fs.t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	verdict := make(chan string, 1)
	go func() { verdict <- echoLeg(fs.t, leg) }()
	if got := readAll(fs.t, conn); got != "hello" {
		fs.t.Fatalf("read %q", got)
	}
	conn.Close()
	if v := <-verdict; v != tunnel.MsgIdle {
		fs.t.Fatalf("the hub's verdict was %q, want idle", v)
	}
	if err := leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle)); err != nil {
		fs.t.Fatal(err)
	}
	waitFor(fs.t, "the leg in the pool", func() bool { return len(fs.f.wordSnap(fs.t).Idle) == 1 })
	return leg
}

// awaitBind reads the idle leg's next frame, which must be a bind.
func awaitBind(t *testing.T, leg *tunnel.Conn) string {
	t.Helper()
	op, payload, err := leg.Next(tunnel.MaxSmallFrame)
	id, ok := strings.CutPrefix(string(payload), tunnel.MsgBind+" ")
	if err != nil || op != tunnel.OpText || !ok {
		t.Fatalf("expected a bind, got %q, %v", payload, err)
	}
	return id
}

func TestReuseBindAndBound(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	leg := fs.keptLeg(c)

	conn := dialEcho(t, c)
	id := awaitBind(t, leg)
	if id != conn.ID().String() {
		t.Fatalf("bind %q for connection %s", id, conn.ID())
	}
	if err := leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" "+id)); err != nil {
		t.Fatal(err)
	}
	go echoLeg(t, leg)
	if got := readAll(t, conn); got != "hello" {
		t.Errorf("read %q", got)
	}
	if w := f.wordSnap(t); w.Reused != 1 {
		t.Errorf("reused %d", w.Reused)
	}
}

// A leg that does not answer bind in time is closed, and the connection
// falls back to an open message, which still works; a late bound is
// ignored.
func TestReuseBindFallsBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(leg *tunnel.Conn, id string)
	}{
		{"silent", func(*tunnel.Conn, string) {}},
		{"late", func(leg *tunnel.Conn, id string) {
			time.Sleep(answerBindWait + 300*time.Millisecond)
			_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" "+id))
		}},
		{"wrong id", func(leg *tunnel.Conn, _ string) {
			_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" 0000000000000000"))
		}},
		{"closes", func(leg *tunnel.Conn, _ string) { _ = leg.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t, "")
			fs := f.fakeServe(t)
			c := f.client(t, testWord, "")
			leg := fs.keptLeg(c)

			conn := dialEcho(t, c)
			id := awaitBind(t, leg)
			go tc.answer(leg, id)
			if again := fs.nextOpen(); again != id {
				t.Fatalf("fell back with open %q, want %q", again, id)
			}
			fresh := fs.accept(id, fs.session)
			go echoLeg(t, fresh)
			if got := readAll(t, conn); got != "hello" {
				t.Errorf("read %q", got)
			}
			// The leg that missed its bind is closed for good.
			leg.SetTimeouts(5*time.Second, time.Second)
			for {
				if _, _, err := leg.Next(1 << 20); err != nil {
					break
				}
			}
		})
	}
}

// legVerdict reads what the hub sends the serving side on leg after the
// connection is over: the data and eofs that come first, then its verdict,
// "idle" or an err:, or "closed".
func legVerdict(t *testing.T, leg *tunnel.Conn) (verdict string, eofs int, data string) {
	t.Helper()
	leg.SetTimeouts(10*time.Second, time.Second)
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			return "closed", eofs, data
		}
		switch {
		case op == tunnel.OpBinary:
			data += string(payload)
		case op == tunnel.OpText && string(payload) == "eof":
			eofs++
		case op == tunnel.OpText:
			return string(payload), eofs, data
		}
	}
}

// keepAndBind answers the hub's idle on leg, opens the next connection and
// checks that it comes to leg with bind.
func (fs *fakeServe) keepAndBind(t *testing.T, c *pfrelay.Client, leg *tunnel.Conn) {
	t.Helper()
	if err := leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the leg to be idle", func() bool { return len(fs.f.wordSnap(t).Idle) == 1 })
	conn := dialEcho(t, c)
	id := awaitBind(t, leg)
	if err := leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" "+id)); err != nil {
		t.Fatal(err)
	}
	if v, _, data := legVerdictEcho(t, leg); v != tunnel.MsgIdle || data != "hello" {
		t.Errorf("the reused leg carried %q and ended with %q, want hello and idle", data, v)
	}
	if got := readAll(t, conn); got != "hello" {
		t.Errorf("the reused leg's connection read %q", got)
	}
}

// legVerdictEcho is echoLeg that also reports the data it carried.
func legVerdictEcho(t *testing.T, leg *tunnel.Conn) (verdict string, eofs int, data string) {
	t.Helper()
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			return "closed", eofs, data
		}
		switch {
		case op == tunnel.OpBinary:
			data += string(payload)
			_ = leg.WriteFrame(tunnel.OpBinary, payload)
		case op == tunnel.OpText && string(payload) == "eof":
			eofs++
			_ = leg.WriteFrame(tunnel.OpText, []byte("eof"))
		case op == tunnel.OpText:
			return string(payload), eofs, data
		}
	}
}

// A connection that fails on the connecting side leaves the serving leg
// healthy: the hub ends the leg's generation with its eof and says idle
// (§12.5). The connection itself still counts as failed.
func TestReuseConnectingSideFailureKeepsTheLeg(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")

	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leg := fs.accept(fs.nextOpen(), fs.session)
	_ = leg.WriteFrame(tunnel.OpBinary, []byte("hi"))
	_ = leg.WriteFrame(tunnel.OpText, []byte("eof"))
	if got := readAll(t, conn); got != "hi" {
		t.Fatalf("read %q", got)
	}
	conn.Fail("the application gave up")
	if v, eofs, _ := legVerdict(t, leg); v != tunnel.MsgIdle || eofs != 1 {
		t.Fatalf("the hub ended the serving leg with %d eof(s) and %q, want 1 and idle", eofs, v)
	}
	fs.keepAndBind(t, c, leg)
	if w := f.wordSnap(t); w.Reused != 1 {
		t.Errorf("%d reused, want 1", w.Reused)
	}
}

// The serving side fails: its reason reaches the connecting side at once,
// and the leg it closed is gone.
func TestReuseServingSideFailureIsNotReused(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn := dialEcho(t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	_ = leg.WriteFrame(tunnel.OpText, []byte("err:the target is down"))
	_ = leg.WriteFrame(tunnel.OpClose, nil)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadAll(conn)
	var remote *pfrelay.RemoteError
	if !errors.As(err, &remote) || remote.Reason != "the target is down" {
		t.Errorf("the connecting side heard %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(f.wordSnap(t).Idle); n != 0 {
		t.Errorf("%d idle legs after the serving side failed", n)
	}
}

// A client that closes instead of answering idle (as one that does not want
// reuse would) loses nothing.
func TestReuseClientDeclines(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn := dialEcho(t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	verdict := make(chan string, 1)
	go func() { verdict <- echoLeg(t, leg) }()
	if got := readAll(t, conn); got != "hello" {
		t.Fatalf("read %q", got)
	}
	if err := conn.Close(); err != nil || conn.Err() != nil {
		t.Errorf("close: %v, %v", err, conn.Err())
	}
	if v := <-verdict; v != tunnel.MsgIdle {
		t.Fatalf("verdict %q", v)
	}
	_ = leg.WriteFrame(tunnel.OpClose, nil)
	time.Sleep(100 * time.Millisecond)
	if n := len(f.wordSnap(t).Idle); n != 0 {
		t.Errorf("%d idle legs", n)
	}
}

// The idle limit closes legs past it, oldest first, down to min idle; a
// takeover closes the rest.
func TestReuseIdleLimitAndTakeover(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.mu.Lock()
	f.hub.reuse.IdleSec, f.hub.reuse.MinIdle, f.hub.reuse.MaxIdle = 1, 1, 4
	f.hub.mu.Unlock()
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	// Three connections at once, so that three legs become idle.
	var conns []*pfrelay.Conn
	var legs []*tunnel.Conn
	for i := 0; i < 3; i++ {
		conns = append(conns, dialEcho(t, c))
		legs = append(legs, fs.accept(fs.nextOpen(), fs.session))
	}
	for i, leg := range legs {
		verdict := make(chan string, 1)
		go func() { verdict <- echoLeg(t, leg) }()
		if got := readAll(t, conns[i]); got != "hello" {
			t.Fatalf("read %q", got)
		}
		conns[i].Close()
		if v := <-verdict; v != tunnel.MsgIdle {
			t.Fatalf("verdict %q", v)
		}
		_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
		waitFor(t, "the leg in the pool", func() bool { return len(f.wordSnap(t).Idle) == i+1 })
	}
	waitFor(t, "the pool to shrink to min idle", func() bool { return len(f.wordSnap(t).Idle) == 1 })
	w := f.wordSnap(t)
	if w.Idle[0].Leg != 3 {
		t.Errorf("kept leg %d, want the newest, 3", w.Idle[0].Leg)
	}
	if il := w.Idle[0]; !il.Kept || il.ClosesAt != 0 {
		t.Errorf("the newest leg: kept %v, closes at %d; want kept by min idle", il.Kept, il.ClosesAt)
	}

	// Another registration takes the word over: the old pool goes.
	f.fakeServe(t)
	waitFor(t, "the pool to close", func() bool {
		ws := f.hub.snapshot().Words
		return len(ws) == 1 && len(ws[0].Idle) == 0
	})
}

// The caps per tenant and per hub, and the switch.
func TestReuseCapsAndSwitch(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*reuseSettings)
	}{
		{"tenant cap", func(r *reuseSettings) { r.TenantCap = 0 }},
		{"hub cap", func(r *reuseSettings) { r.HubCap = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t, "")
			f.hub.mu.Lock()
			tc.set(&f.hub.reuse)
			f.hub.mu.Unlock()
			fs := f.fakeServe(t)
			c := f.client(t, testWord, "")
			conn := dialEcho(t, c)
			leg := fs.accept(fs.nextOpen(), fs.session)
			verdict := make(chan string, 1)
			go func() { verdict <- echoLeg(t, leg) }()
			if got := readAll(t, conn); got != "hello" {
				t.Fatalf("read %q", got)
			}
			if v := <-verdict; v != tunnel.MsgIdle {
				t.Fatalf("verdict %q", v)
			}
			_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
			// Over the cap: closed, not pooled.
			leg.SetTimeouts(5*time.Second, time.Second)
			if _, _, err := leg.Next(1 << 20); err == nil {
				t.Error("the leg over the cap was not closed")
			}
			if n := len(f.wordSnap(t).Idle); n != 0 {
				t.Errorf("%d idle legs over the cap", n)
			}
		})
	}
	t.Run("switched off", func(t *testing.T) {
		f := newRelayFixture(t, "")
		f.hub.mu.Lock()
		f.hub.reuse.Enabled = false
		f.hub.mu.Unlock()
		fs := f.fakeServe(t)
		c := f.client(t, testWord, "")
		conn := dialEcho(t, c)
		leg := fs.accept(fs.nextOpen(), fs.session)
		if v := leg.Header.Get(tunnel.HeaderKeepAlive); v != "" {
			t.Errorf("offered reuse while it is off: %q", v)
		}
		go echoLeg(t, leg)
		if got := readAll(t, conn); got != "hello" {
			t.Errorf("read %q", got)
		}
		if f.wordSnap(t).Reuse {
			t.Error("the console shows reuse on")
		}
	})
}

// A leg min idle keeps shows as kept from the start. Once a newer leg pushes
// it out of min idle past the idle limit, it closes at once; one that is
// pushed out before the limit shows when it will close.
func TestReuseMinIdleHandsOver(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.mu.Lock()
	f.hub.reuse.IdleSec, f.hub.reuse.MinIdle, f.hub.reuse.MaxIdle = 3, 1, 4
	f.hub.mu.Unlock()
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	var conns []*pfrelay.Conn
	var legs []*tunnel.Conn
	for i := 0; i < 3; i++ {
		conns = append(conns, dialEcho(t, c))
		legs = append(legs, fs.accept(fs.nextOpen(), fs.session))
	}
	idle := func(i int) {
		t.Helper()
		verdict := make(chan string, 1)
		go func() { verdict <- echoLeg(t, legs[i]) }()
		if got := readAll(t, conns[i]); got != "hello" {
			t.Fatalf("read %q", got)
		}
		conns[i].Close()
		if v := <-verdict; v != tunnel.MsgIdle {
			t.Fatalf("verdict %q", v)
		}
		_ = legs[i].WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
		waitFor(t, "the leg in the pool", func() bool {
			for _, il := range f.wordSnap(t).Idle {
				if il.Leg == i+1 {
					return true
				}
			}
			return false
		})
	}
	legsIdle := func() []idleSnapshot { return f.wordSnap(t).Idle }

	idle(0)
	if p := legsIdle(); len(p) != 1 || !p[0].Kept || p[0].ClosesAt != 0 {
		t.Fatalf("the only idle leg: %+v; want kept by min idle", p)
	}
	time.Sleep(3300 * time.Millisecond) // past the idle limit
	if p := legsIdle(); len(p) != 1 || !p[0].Kept {
		t.Fatalf("past the idle limit: %+v; want leg 1 kept", p)
	}

	// Leg 1 leaves the pool in the same step that leg 2 enters it.
	idle(1)
	if p := legsIdle(); len(p) != 1 || p[0].Leg != 2 {
		t.Fatalf("pool %+v once leg 2 is in it; want leg 1 gone at once", p)
	}

	idle(2)
	p := legsIdle()
	if len(p) != 2 || p[0].Leg != 2 || p[1].Leg != 3 {
		t.Fatalf("pool %+v, want legs 2 and 3", p)
	}
	if p[0].Kept || p[0].ClosesAt != p[0].Since+3000 {
		t.Errorf("leg 2: kept %v, closes at %d; want closing at %d", p[0].Kept, p[0].ClosesAt, p[0].Since+3000)
	}
	if !p[1].Kept || p[1].ClosesAt != 0 {
		t.Errorf("leg 3: kept %v, closes at %d; want kept", p[1].Kept, p[1].ClosesAt)
	}
	waitFor(t, "leg 2 to reach the idle limit", func() bool { p := legsIdle(); return len(p) == 1 && p[0].Leg == 3 })

	// The word's own limits reach the legs already in the pool: with no min
	// idle, leg 3, past the limit, closes as soon as they are set.
	time.Sleep(time.Until(time.UnixMilli(legsIdle()[0].Since).Add(3300 * time.Millisecond)))
	three, zero := 3, 0
	if err := f.hub.setWordReuse(f.wordSnap(t).ID, &wordReuse{IdleSec: &three, MinIdle: &zero}); err != nil {
		t.Fatal(err)
	}
	if p := legsIdle(); len(p) != 0 {
		t.Errorf("pool %+v after min idle went to 0; want leg 3 closed at once", p)
	}
}

// A word's own idle limit reaches a leg already idle, one that has not yet
// reached the limit it had when it went into the pool.
func TestReuseWordIdleLimitReachesPooledLegs(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.mu.Lock()
	f.hub.reuse.IdleSec, f.hub.reuse.MinIdle, f.hub.reuse.MaxIdle = 60, 0, 4
	f.hub.mu.Unlock()
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn := dialEcho(t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	verdict := make(chan string, 1)
	go func() { verdict <- echoLeg(t, leg) }()
	if got := readAll(t, conn); got != "hello" {
		t.Fatalf("read %q", got)
	}
	conn.Close()
	if v := <-verdict; v != tunnel.MsgIdle {
		t.Fatalf("verdict %q", v)
	}
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	waitFor(t, "the leg in the pool", func() bool { return len(f.wordSnap(t).Idle) == 1 })

	three, zero := 3, 0
	if err := f.hub.setWordReuse(f.wordSnap(t).ID, &wordReuse{IdleSec: &three, MinIdle: &zero}); err != nil {
		t.Fatal(err)
	}
	if p := f.wordSnap(t).Idle; len(p) != 1 || p[0].ClosesAt != p[0].Since+3000 {
		t.Fatalf("pool %+v; want the leg closing 3s after it went idle", p)
	}
	waitFor(t, "the leg to reach the word's idle limit", func() bool { return len(f.wordSnap(t).Idle) == 0 })
}

// With min idle equal to max idle, a full pool of legs past the limit still
// takes a new leg: the oldest makes way for it.
func TestReuseFullKeptPoolTakesANewLeg(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.mu.Lock()
	f.hub.reuse.IdleSec, f.hub.reuse.MinIdle, f.hub.reuse.MaxIdle = 1, 1, 1
	f.hub.mu.Unlock()
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conns := []*pfrelay.Conn{dialEcho(t, c), dialEcho(t, c)}
	legs := []*tunnel.Conn{fs.accept(fs.nextOpen(), fs.session), fs.accept(fs.nextOpen(), fs.session)}
	for i := range legs {
		if i == 1 {
			time.Sleep(1300 * time.Millisecond) // leg 1 past the idle limit, kept
		}
		verdict := make(chan string, 1)
		go func() { verdict <- echoLeg(t, legs[i]) }()
		if got := readAll(t, conns[i]); got != "hello" {
			t.Fatalf("read %q", got)
		}
		conns[i].Close()
		if v := <-verdict; v != tunnel.MsgIdle {
			t.Fatalf("verdict %q", v)
		}
		_ = legs[i].WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
		waitFor(t, "the leg in the pool", func() bool {
			p := f.wordSnap(t).Idle
			return len(p) == 1 && p[0].Leg == i+1
		})
	}
}

// The limits on reuse are kept in [tunnel.reuse], changed in the console,
// and a word may have its own, kept with its binding.
func TestReuseSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.toml")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Defaults, and a table that changes some of them.
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n")
	if cfg, err := loadConfig(path, ""); err != nil || cfg.tunnel.reuse != defaultReuse {
		t.Fatalf("defaults = %+v, %v", cfg.tunnel, err)
	}
	if defaultReuse.MinIdle != 3 || defaultReuse.MaxIdle != 10 || defaultReuse.IdleSec != 60 || !defaultReuse.Enabled {
		t.Errorf("defaults = %+v; want min 3, max 10, 60 s, on", defaultReuse)
	}
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n[tunnel.reuse]\nmin_idle = 1\nmax_idle = 4\nidle_seconds = 30\n")
	cfg, err := loadConfig(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.tunnel.reuse; r.MinIdle != 1 || r.MaxIdle != 4 || r.IdleSec != 30 || !r.Enabled || r.HubCap != defaultReuse.HubCap {
		t.Fatalf("[tunnel.reuse] = %+v", r)
	}
	for _, bad := range []string{"min_idle = 5\nmax_idle = 4", "idle_seconds = 0", "idle_seconds = 3601", "max_idle = -1"} {
		write("[console]\nlisten = \"18222\"\n\n[tunnel]\n[tunnel.reuse]\n" + bad + "\n")
		if _, err := loadConfig(path, ""); err == nil || !strings.Contains(err.Error(), "[tunnel.reuse]") {
			t.Errorf("%q: %v", bad, err)
		}
	}

	// The console changes them, and they are saved.
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n")
	cfg, _ = loadConfig(path, "")
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.tunnelRaw = cfg.configPath, cfg.consoleRaw, cfg.tunnelRaw
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, relayStatePath(path))
	hub.persistSettings, hub.persistReuse = mgr.saveTunnelSettings, mgr.saveTunnelReuse
	hub.guesses.limit = 1 << 30
	cs.tunnels = hub
	srv := httptest.NewTLSServer(cs.handler())
	defer func() { hub.closeAll(); srv.CloseClientConnections(); srv.Close() }()
	post := func(p, body string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/pf/api/"+p, strings.NewReader(body))
		req.Header.Set(csrfHeader, "1")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("POST %s %s = %d %s, want %d", p, body, resp.StatusCode, b, want)
		}
		return b
	}
	post("relay/settings", `{"reuse":{"enabled":true,"idleSeconds":45,"minIdle":2,"maxIdle":6,"tenantCap":100,"hubCap":1000}}`, http.StatusOK)
	if cfg, err := loadConfig(path, ""); err != nil || cfg.tunnel.reuse != (reuseSettings{true, 45, 2, 6, 100, 1000}) {
		t.Fatalf("saved = %+v, %v", cfg.tunnel.reuse, err)
	}
	post("relay/settings", `{"reuse":{"enabled":true,"idleSeconds":45,"minIdle":7,"maxIdle":6,"tenantCap":100,"hubCap":1000}}`, http.StatusBadRequest)

	// A word's own limits; they outlive a restart with the binding.
	f := &relayFixture{hub: hub, srv: srv, tls: srv.Client().Transport.(*http.Transport).TLSClientConfig, url: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.goServeWith(t, ctx, echoTarget(t), nil)
	id := strconv.Itoa(f.wordSnap(t).ID)
	post("relay/"+id+"/reuse", `{"minIdle":0,"maxIdle":1}`, http.StatusOK)
	if w := f.wordSnap(t); w.MinIdle != 0 || w.MaxIdle != 1 || w.IdleSec != 45 || w.WordReuse == nil {
		t.Errorf("with the word's own limits: min %d, max %d, idle %d", w.MinIdle, w.MaxIdle, w.IdleSec)
	}
	post("relay/"+id+"/reuse", `{"maxIdle":2000}`, http.StatusBadRequest)
	again := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, relayStatePath(path))
	if ws := again.snapshot().Words; len(ws) != 1 || ws[0].WordReuse == nil || *ws[0].WordReuse.MaxIdle != 1 {
		t.Errorf("after a restart, the word's limits are %+v", ws)
	}
	post("relay/"+id+"/reuse", `{}`, http.StatusOK)
	if w := f.wordSnap(t); w.WordReuse != nil || w.MaxIdle != 6 {
		t.Errorf("after clearing, the word's limits are %+v, max %d", w.WordReuse, w.MaxIdle)
	}

	// Closing an idle leg by hand.
	c := f.client(t, testWord, "")
	echoOnce(t, c, "hello")
	waitFor(t, "an idle leg", func() bool { return len(f.wordSnap(t).Idle) == 1 })
	leg := strconv.Itoa(f.wordSnap(t).Idle[0].Leg)
	post("relay/"+id+"/legs/"+leg+"/close", ``, http.StatusNoContent)
	if n := len(f.wordSnap(t).Idle); n != 0 {
		t.Errorf("%d idle legs after closing it", n)
	}
	post("relay/"+id+"/legs/"+leg+"/close", ``, http.StatusNotFound)
	echoOnce(t, c, "still works")
}

// A client that says nothing after the hub's idle gets its leg closed once
// the hub has waited long enough.
func TestReuseIdleAnswerTimesOut(t *testing.T) {
	defer func(d time.Duration) { answerIdleWait = d }(answerIdleWait)
	answerIdleWait = 300 * time.Millisecond
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn := dialEcho(t, c)
	leg := fs.accept(fs.nextOpen(), fs.session)
	verdict := make(chan string, 1)
	go func() { verdict <- echoLeg(t, leg) }()
	if got := readAll(t, conn); got != "hello" {
		t.Fatalf("read %q", got)
	}
	if v := <-verdict; v != tunnel.MsgIdle {
		t.Fatalf("verdict %q", v)
	}
	start := time.Now()
	leg.SetTimeouts(5*time.Second, time.Second)
	if _, _, err := leg.Next(1 << 20); err == nil {
		t.Fatal("the hub kept a leg whose client did not answer")
	}
	if took := time.Since(start); took < 250*time.Millisecond || took > 3*time.Second {
		t.Errorf("closed after %s, want about %s", took, answerIdleWait)
	}
	if n := len(f.wordSnap(t).Idle); n != 0 {
		t.Errorf("%d idle legs", n)
	}
}

// An idle leg that has gone quiet (its pings are no longer answered) is
// closed when the hub would bind it, and the connection goes straight to an
// open message instead of waiting on it.
func TestReuseStaleLegIsSkipped(t *testing.T) {
	defer func(d time.Duration) { staleIdleLeg = d }(staleIdleLeg)
	staleIdleLeg = 300 * time.Millisecond
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	leg := fs.keptLeg(c) // nothing reads it from here on: it answers no ping
	time.Sleep(600 * time.Millisecond)

	conn := dialEcho(t, c)
	start := time.Now()
	id := fs.nextOpen()
	if took := time.Since(start); took > answerBindWait/2 {
		t.Errorf("the open message came after %s: the stale leg was bound and waited on", took)
	}
	fresh := fs.accept(id, fs.session)
	go echoLeg(t, fresh)
	if got := readAll(t, conn); got != "hello" {
		t.Errorf("read %q", got)
	}
	leg.SetTimeouts(5*time.Second, time.Second)
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			break
		}
		if op == tunnel.OpText && strings.HasPrefix(string(payload), tunnel.MsgBind) {
			t.Fatal("the stale leg was bound")
		}
	}
}

// On an idle leg, unknown text is ignored (§8.1), and a known frame in the
// wrong state closes it (§12.4).
func TestReuseIdleLegFrames(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	leg := fs.keptLeg(c)
	_ = leg.WriteFrame(tunnel.OpText, []byte("something from a later protocol"))
	time.Sleep(100 * time.Millisecond)
	if n := len(f.wordSnap(t).Idle); n != 1 {
		t.Fatalf("unknown text closed the idle leg (%d idle)", n)
	}
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle)) // idle again, while idle
	waitFor(t, "the leg to be closed", func() bool { return len(f.wordSnap(t).Idle) == 0 })
}

// One client that both serves and connects through its word: its own
// connecting connections share ids with what it serves, and must never be
// taken for an attempt the hub asked for again (§12.7).
func TestReuseServeAndDialOneClient(t *testing.T) {
	for _, proto := range []int{1, 2} {
		t.Run(fmt.Sprintf("protocol %d", proto), func(t *testing.T) {
			f := newRelayFixture(t, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := f.client(t, testWord, testServeToken)
			c.MaxProto = proto
			go func() { _ = c.Serve(ctx, echoTarget(t)) }()
			waitFor(t, "the word to be served", func() bool { return c.Check(ctx) == nil })
			for i := 0; i < 20; i++ {
				echoOnce(t, c, "hello")
			}
			if st := c.Stats(); st.Failed != 0 {
				t.Errorf("stats = %+v", st)
			}
		})
	}
}

// The connecting side half-closes and then fails while the serving side
// is still sending: what the serving side sends after that belongs to the
// connection that is over. The hub drops it, up to the serving side's eof,
// and the leg's next connection sees none of it.
func TestReuseConnectingSideFailsAfterHalfClose(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leg := fs.accept(fs.nextOpen(), fs.session)
	_ = conn.CloseWrite()
	conn.Fail("the application gave up")
	time.Sleep(100 * time.Millisecond)
	_ = leg.WriteFrame(tunnel.OpBinary, []byte("late"))
	_ = leg.WriteFrame(tunnel.OpText, []byte("eof"))
	if v, eofs, _ := legVerdict(t, leg); v != tunnel.MsgIdle || eofs != 1 {
		t.Fatalf("the hub ended the serving leg with %d eof(s) and %q, want 1 and idle", eofs, v)
	}
	fs.keepAndBind(t, c, leg) // and "late" is not what its connection reads
}

// The connecting side's link drops without a word: the serving leg is
// still healthy, and is reused.
func TestReuseConnectingLinkLostKeepsTheLeg(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	h := http.Header{}
	h.Set(tunnel.HeaderWord, testWord)
	h.Set(tunnel.HeaderProto, "0-2")
	ws, err := tunnel.Dial(context.Background(), f.srv.URL+tunnel.Path+"/connect", h, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	leg := fs.accept(fs.nextOpen(), fs.session)
	_ = ws.WriteFrame(tunnel.OpBinary, []byte("hello"))
	if op, payload, err := leg.Next(1 << 20); err != nil || op != tunnel.OpBinary || string(payload) != "hello" {
		t.Fatalf("the serving leg got %v %q %v", op, payload, err)
	}
	ws.Close() // gone, no close handshake
	// The serving side hears the hub's eof (its target is half-closed),
	// and finishes with its own.
	if v, eofs, _ := legVerdictEcho(t, leg); v != tunnel.MsgIdle || eofs != 1 {
		t.Fatalf("the hub ended the serving leg with %d eof(s) and %q, want 1 and idle", eofs, v)
	}
	fs.keepAndBind(t, c, leg)
}

// The target closes, the application keeps its end open, and the hub's
// half-close idle rule ends the connection: the serving leg had finished
// its part, and is reused.
func TestReuseHalfCloseIdleTimeoutKeepsTheLeg(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.idle = 300 * time.Millisecond
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leg := fs.accept(fs.nextOpen(), fs.session)
	_ = leg.WriteFrame(tunnel.OpText, []byte("eof")) // the target closed
	start := time.Now()
	if v, eofs, _ := legVerdict(t, leg); v != tunnel.MsgIdle || eofs != 1 {
		t.Fatalf("the hub ended the serving leg with %d eof(s) and %q, want 1 and idle", eofs, v)
	}
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Errorf("idle after %v, before the half-close idle rule", d)
	}
	_ = conn
	fs.keepAndBind(t, c, leg)
}

// A serving side that keeps sending after the hub's eof, past the grace,
// costs the leg: the hub cannot wait for ever to finish its generation.
func TestReuseServingSideThatNeverFinishesLosesTheLeg(t *testing.T) {
	defer func(d time.Duration) { generationWait = d }(generationWait)
	generationWait = 300 * time.Millisecond
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	conn, err := c.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leg := fs.accept(fs.nextOpen(), fs.session)
	conn.Fail("the application gave up")
	stop := make(chan struct{})
	defer close(stop)
	go func() { // a target that ignores the half-close and keeps talking
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				if leg.WriteFrame(tunnel.OpBinary, []byte("more")) != nil {
					return
				}
			}
		}
	}()
	if v, _, _ := legVerdict(t, leg); v == tunnel.MsgIdle {
		t.Error("the hub said idle on a leg whose generation never ended")
	} else if v != "closed" {
		if _, _, err := leg.Next(1 << 20); err == nil {
			t.Errorf("the hub said %q and kept the leg open", v)
		}
	}
	if n := len(f.wordSnap(t).Idle); n != 0 {
		t.Errorf("%d idle legs", n)
	}
}

// Lowering the limits applies to the legs already idle: the caps close the
// oldest, and a shorter idle limit applies at once.
func TestReuseLoweredLimitsApply(t *testing.T) {
	f := newRelayFixture(t, "")
	f.hub.persistReuse = func(reuseSettings) error { return nil }
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	var conns []*pfrelay.Conn
	var legs []*tunnel.Conn
	for i := 0; i < 3; i++ {
		conns = append(conns, dialEcho(t, c))
		legs = append(legs, fs.accept(fs.nextOpen(), fs.session))
	}
	for i, leg := range legs {
		verdict := make(chan string, 1)
		go func() { verdict <- echoLeg(t, leg) }()
		readAll(t, conns[i])
		conns[i].Close()
		<-verdict
		_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
		waitFor(t, "the leg in the pool", func() bool { return len(f.wordSnap(t).Idle) == i+1 })
	}
	r := defaultReuse
	r.TenantCap = 2
	if err := f.hub.setReuse(r); err != nil {
		t.Fatal(err)
	}
	if w := f.wordSnap(t); len(w.Idle) != 2 || w.Idle[0].Leg != 2 {
		t.Errorf("after a tenant cap of 2: %+v", w.Idle)
	}
	r.TenantCap, r.IdleSec, r.MinIdle = 256, 1, 0
	if err := f.hub.setReuse(r); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the shorter idle limit", func() bool { return len(f.wordSnap(t).Idle) == 0 })
}

// A serving side that refuses after bound: the flow log and the counters
// show a failure, as for a refusal at accept.
func TestReuseRefusalAfterBoundIsAFailure(t *testing.T) {
	f := newRelayFixture(t, "")
	fs := f.fakeServe(t)
	c := f.client(t, testWord, "")
	leg := fs.keptLeg(c)
	before := f.wordSnap(t).Failed
	conn := dialEcho(t, c)
	id := awaitBind(t, leg)
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBound+" "+id))
	_ = leg.WriteFrame(tunnel.OpText, []byte("err:the serving side could not reach its target"))
	_ = leg.WriteFrame(tunnel.OpClose, nil)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(conn); err == nil {
		t.Fatal("no failure")
	}
	waitFor(t, "a failure counted", func() bool { return f.wordSnap(t).Failed == before+1 })
}

// Settings: reuse must be whole, and a bad one changes nothing.
func TestReuseSettingsAreWhole(t *testing.T) {
	cfg, err := parseArgs([]string{"--console", "18222@secret", "--tunnel", testServeToken}, io.Discard, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.tunnel.reuse != defaultReuse {
		t.Errorf("a hub from the command line reuses with %+v, want the defaults", cfg.tunnel.reuse)
	}
}
