package pfrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The serving side's half of reusing accept legs (protocol 2,
// docs/PROTOCOL.md §12), against a hub whose every frame the test writes.

const scriptSession = "0123456789abcdef0123456789abcdef"

type acceptReq struct {
	id, session string
	ws          *tunnel.Conn
}

// scriptHub answers serve and accept as a protocol 2 hub would, and hands
// the WebSockets to the test.
type scriptHub struct {
	t       *testing.T
	srv     *httptest.Server
	ctl     chan *tunnel.Conn
	accepts chan acceptReq
	mu      sync.Mutex
	offer   bool // offer reuse on accepts that bring the session
}

func newScriptHub(t *testing.T) *scriptHub {
	h := &scriptHub{t: t, ctl: make(chan *tunnel.Conn, 4), accepts: make(chan acceptReq, 16), offer: true}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(tunnel.HeaderProto, "2")
		switch strings.TrimPrefix(r.URL.Path, tunnel.Path) {
		case "/serve":
			w.Header().Set(tunnel.HeaderSession, scriptSession)
			ws, err := tunnel.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			h.ctl <- ws
		case "/accept":
			if r.Header.Get(tunnel.HeaderError) != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			sess := r.Header.Get(tunnel.HeaderSession)
			h.mu.Lock()
			if h.offer && sess == scriptSession {
				w.Header().Set(tunnel.HeaderKeepAlive, "60")
			}
			h.mu.Unlock()
			ws, err := tunnel.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			h.accepts <- acceptReq{r.Header.Get(tunnel.HeaderConn), sess, ws}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *scriptHub) client(t *testing.T) *Client {
	c, err := NewClient(h.srv.URL, "k3f9-x2mq-7hpa", h.srv.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	c.ServeToken, c.Name = strings.Repeat("s", tunnel.MinSecret), "Script"
	return c
}

func (h *scriptHub) nextCtl() *tunnel.Conn {
	h.t.Helper()
	select {
	case ws := <-h.ctl:
		// Held until the test ends: a socket whose last reference goes is
		// closed by the garbage collector, which would end the registration.
		h.t.Cleanup(func() { ws.Close() })
		return ws
	case <-time.After(10 * time.Second):
		h.t.Fatal("no registration")
	}
	return nil
}

func (h *scriptHub) nextAccept() acceptReq {
	h.t.Helper()
	select {
	case a := <-h.accepts:
		h.t.Cleanup(func() { a.ws.Close() })
		return a
	case <-time.After(10 * time.Second):
		h.t.Fatal("no accept")
	}
	return acceptReq{}
}

func open(t *testing.T, ctl *tunnel.Conn, id string) {
	t.Helper()
	if err := ctl.WriteFrame(tunnel.OpText, []byte(`{"open":"`+id+`"}`)); err != nil {
		t.Fatal(err)
	}
}

// exchange runs one connection on a leg from the hub's side, against an
// echo on the client's: data, the hub's half-close, then the echo and the
// client's half-close.
func exchange(t *testing.T, leg *tunnel.Conn) {
	t.Helper()
	_ = leg.WriteFrame(tunnel.OpBinary, []byte("hi"))
	_ = leg.WriteFrame(tunnel.OpText, []byte("eof"))
	var got []byte
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			t.Fatalf("after %q: %v", got, err)
		}
		if op == tunnel.OpBinary {
			got = append(got, payload...)
		}
		if op == tunnel.OpText && string(payload) == "eof" {
			break
		}
	}
	if string(got) != "hi" {
		t.Fatalf("echoed %q", got)
	}
}

// expectText reads the leg's next text frame.
func expectText(t *testing.T, leg *tunnel.Conn, within time.Duration) (string, error) {
	t.Helper()
	leg.SetTimeouts(within, time.Second)
	for {
		op, payload, err := leg.Next(1 << 20)
		if err != nil {
			return "", err
		}
		if op == tunnel.OpText {
			return string(payload), nil
		}
	}
}

// events records a client's connection events.
type events struct {
	mu     sync.Mutex
	opened []ConnID
	closed map[ConnID][]error
}

func (e *events) install(c *Client) {
	e.closed = map[ConnID][]error{}
	c.Events.OnOpen = func(ci ConnInfo) { e.mu.Lock(); e.opened = append(e.opened, ci.ID); e.mu.Unlock() }
	c.Events.OnClose = func(ci ConnInfo, err error) {
		e.mu.Lock()
		e.closed[ci.ID] = append(e.closed[ci.ID], err)
		e.mu.Unlock()
	}
}

func (e *events) closedWith(t *testing.T, id string) []error {
	t.Helper()
	var out []error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		out = e.closed[ConnID{id}]
		e.mu.Unlock()
		if len(out) > 0 {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connection %s never closed", id)
	return nil
}

// waitOpened waits until connection id has opened.
func (e *events) waitOpened(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		for _, o := range e.opened {
			if o == (ConnID{id}) {
				e.mu.Unlock()
				return
			}
		}
		e.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connection %s never opened", id)
}

// listenEcho serves with Listen, echoing every connection.
func listenEcho(t *testing.T, c *Client) *Listener {
	t.Helper()
	l, err := c.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.AcceptConn()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.CloseWrite()
				_ = conn.Close()
			}()
		}
	}()
	return l
}

// keepLeg runs connection id on a fresh leg, gives the hub's idle and checks
// the client keeps the leg.
func keepLeg(t *testing.T, h *scriptHub, ctl *tunnel.Conn, id string) *tunnel.Conn {
	t.Helper()
	open(t, ctl, id)
	a := h.nextAccept()
	if a.id != id || a.session != scriptSession {
		t.Fatalf("accept %q with session %q", a.id, a.session)
	}
	exchange(t, a.ws)
	_ = a.ws.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	if v, err := expectText(t, a.ws, 5*time.Second); v != tunnel.MsgIdle {
		t.Fatalf("the client answered the hub's idle with %q, %v", v, err)
	}
	return a.ws
}

func TestClientKeepsAndBindsLegs(t *testing.T) {
	for _, mode := range []string{"listen", "forward"} {
		t.Run(mode, func(t *testing.T) {
			h := newScriptHub(t)
			c := h.client(t)
			var ev events
			ev.install(c)
			if mode == "listen" {
				listenEcho(t, c)
			} else {
				go func() { _ = c.Serve(testCtx(t), echoTarget(t)) }()
			}
			ctl := h.nextCtl()
			leg := keepLeg(t, h, ctl, "1111111111111111")
			if errs := ev.closedWith(t, "1111111111111111"); len(errs) != 1 || errs[0] != nil {
				t.Errorf("the first connection closed with %v", errs)
			}

			// The hub binds the idle leg: answered at once, and carried.
			_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
			if v, err := expectText(t, leg, 5*time.Second); v != tunnel.MsgBound+" 2222222222222222" {
				t.Fatalf("bind answered with %q, %v", v, err)
			}
			exchange(t, leg)
			_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
			if v, _ := expectText(t, leg, 5*time.Second); v != tunnel.MsgIdle {
				t.Fatalf("the reused leg was not kept again: %q", v)
			}
			if errs := ev.closedWith(t, "2222222222222222"); len(errs) != 1 || errs[0] != nil {
				t.Errorf("the second connection closed with %v", errs)
			}
			if st := c.Stats(); st.Opened != 2 || st.Failed != 0 || st.Active != 0 {
				t.Errorf("stats = %+v", st)
			}
		})
	}
}

// Without the hub's verdict in time, the client closes as in protocol 1;
// with err: instead, the connection failed.
func TestClientVerdict(t *testing.T) {
	defer func(d time.Duration) { verdictWait = d }(verdictWait)
	verdictWait = 200 * time.Millisecond
	h := newScriptHub(t)
	c := h.client(t)
	var ev events
	ev.install(c)
	listenEcho(t, c)
	ctl := h.nextCtl()

	open(t, ctl, "1111111111111111")
	a := h.nextAccept()
	exchange(t, a.ws)
	start := time.Now()
	if _, err := expectText(t, a.ws, 5*time.Second); err == nil {
		t.Fatal("the client sent a text frame without a verdict")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("closed after %s, want about %s", took, verdictWait)
	}
	if errs := ev.closedWith(t, "1111111111111111"); errs[0] != nil {
		t.Errorf("no verdict: closed with %v, want a clean finish", errs[0])
	}

	open(t, ctl, "2222222222222222")
	a = h.nextAccept()
	exchange(t, a.ws)
	_ = a.ws.WriteFrame(tunnel.OpText, []byte("err:the application side failed"))
	_ = a.ws.WriteFrame(tunnel.OpClose, nil)
	var remote *RemoteError
	if errs := ev.closedWith(t, "2222222222222222"); !errors.As(errs[0], &remote) || remote.Reason != "the application side failed" {
		t.Errorf("err: as the verdict: closed with %v", errs[0])
	}
}

// Without the offer, nothing waits: the client closes at once.
func TestClientWithoutOffer(t *testing.T) {
	h := newScriptHub(t)
	h.offer = false
	c := h.client(t)
	listenEcho(t, c)
	ctl := h.nextCtl()
	open(t, ctl, "1111111111111111")
	a := h.nextAccept()
	exchange(t, a.ws)
	start := time.Now()
	if v, err := expectText(t, a.ws, 5*time.Second); err == nil {
		t.Fatalf("sent %q on a leg without the offer", v)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("closed after %s", took)
	}
}

// The client keeps at most MaxIdleLegs; past that it answers the hub's idle
// with a close. Losing the registration closes its idle legs.
func TestClientIdleCapAndRegistrationLoss(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	c.MaxIdleLegs = 1
	listenEcho(t, c)
	ctl := h.nextCtl()
	kept := keepLeg(t, h, ctl, "1111111111111111")

	open(t, ctl, "2222222222222222")
	a := h.nextAccept()
	exchange(t, a.ws)
	_ = a.ws.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	if v, err := expectText(t, a.ws, 5*time.Second); err == nil {
		t.Fatalf("a leg over the client's cap was answered with %q", v)
	}

	ctl.Close() // the registration ends
	if _, err := expectText(t, kept, 5*time.Second); err == nil {
		t.Fatal("the idle leg outlived its registration")
	}
}

// An id the client answered bound to that comes back with an open message
// is a new attempt: the old one is reported failed, the new one carried.
func TestClientReopenedID(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	var ev events
	ev.install(c)
	listenEcho(t, c)
	ctl := h.nextCtl()
	leg := keepLeg(t, h, ctl, "1111111111111111")
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
	if v, _ := expectText(t, leg, 5*time.Second); v != tunnel.MsgBound+" 2222222222222222" {
		t.Fatalf("bind answered with %q", v)
	}
	// Wait until the bound attempt has opened. "bound" goes out before the
	// connection is handed on, so an open message sent at once may overtake
	// it; the attempt is then given up before it opens, and reports nothing
	// (it never opened), which is the other case and not this test's.
	ev.waitOpened(t, "2222222222222222")
	// The hub never heard bound, and asks again.
	open(t, ctl, "2222222222222222")
	a := h.nextAccept()
	if a.id != "2222222222222222" {
		t.Fatalf("accept for %q", a.id)
	}
	exchange(t, a.ws)
	_ = a.ws.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	_, _ = expectText(t, a.ws, 5*time.Second)
	var errs []error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if errs = ev.closedWith(t, "2222222222222222"); len(errs) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(errs) != 2 {
		t.Fatalf("closed %d times, want 2 (the abandoned attempt and the new one)", len(errs))
	}
	var dropped *DroppedError
	failed, clean := 0, 0
	for _, err := range errs {
		switch {
		case errors.As(err, &dropped) && dropped.Reason == reasonLegLost:
			failed++
		case err == nil:
			clean++
		}
	}
	if failed != 1 || clean != 1 {
		t.Errorf("closed with %v; want one abandoned attempt and one clean finish", errs)
	}
}

// After bound, a forwarder that cannot reach its target refuses with err:.
func TestForwarderUnreachableAfterBound(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); conn.Close() }()
		}
	}()
	go func() { _ = c.Serve(testCtx(t), ln.Addr().String()) }()
	ctl := h.nextCtl()
	leg := keepLeg(t, h, ctl, "1111111111111111")
	ln.Close()
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
	if v, _ := expectText(t, leg, 5*time.Second); v != tunnel.MsgBound+" 2222222222222222" {
		t.Fatalf("bind answered with %q", v)
	}
	if v, _ := expectText(t, leg, 10*time.Second); !strings.HasPrefix(v, "err:") {
		t.Errorf("an unreachable target after bound gave %q, want err:", v)
	}
}

// testCtx ends when the test does, so nothing it started outlives it.
func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// echoTarget echoes each TCP connection until its client half-closes.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String()
}

// On the client's idle leg, unknown text is ignored and a bind still works;
// a known frame in the wrong state closes the leg.
func TestClientIdleLegFrames(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	listenEcho(t, c)
	ctl := h.nextCtl()
	leg := keepLeg(t, h, ctl, "1111111111111111")
	_ = leg.WriteFrame(tunnel.OpText, []byte("something from a later protocol"))
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
	if v, _ := expectText(t, leg, 5*time.Second); v != tunnel.MsgBound+" 2222222222222222" {
		t.Fatalf("after unknown text, bind answered with %q", v)
	}
	exchange(t, leg)
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	if v, _ := expectText(t, leg, 5*time.Second); v != tunnel.MsgIdle {
		t.Fatalf("not kept again: %q", v)
	}
	_ = leg.WriteFrame(tunnel.OpText, []byte("eof")) // a stream frame on an idle leg
	if v, err := expectText(t, leg, 5*time.Second); err == nil {
		t.Fatalf("a known frame in the wrong state was answered with %q", v)
	}
}

// An idle leg that ends without a bind (the hub's idle limit, a dead link)
// gives its place back: with MaxIdleLegs 1, the next leg is kept again.
func TestClientIdleLegGivesItsPlaceBack(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	c.MaxIdleLegs = 1
	listenEcho(t, c)
	ctl := h.nextCtl()
	for i, id := range []string{"1111111111111111", "2222222222222222", "3333333333333333"} {
		leg := keepLeg(t, h, ctl, id)           // fails if the client has no place left
		_ = leg.WriteFrame(tunnel.OpClose, nil) // the hub lets the idle leg go
		if _, err := expectText(t, leg, 5*time.Second); err == nil {
			t.Fatalf("leg %d: not closed", i+1)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A bound attempt the hub asks for again is abandoned and reported failed,
// even when the application holding it closes it quietly; the new attempt
// is carried.
func TestClientAbandonedAttemptIsFailed(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	var ev events
	ev.install(c)
	l, err := c.Listen(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	held := make(chan *Conn, 4)
	go func() {
		for {
			conn, err := l.AcceptConn()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	ctl := h.nextCtl()
	open(t, ctl, "1111111111111111")
	a := h.nextAccept()
	first := <-held
	go func() { _, _ = io.Copy(first, first); _ = first.CloseWrite(); _ = first.Close() }()
	exchange(t, a.ws)
	_ = a.ws.WriteFrame(tunnel.OpText, []byte(tunnel.MsgIdle))
	if v, _ := expectText(t, a.ws, 5*time.Second); v != tunnel.MsgIdle {
		t.Fatalf("not kept: %q", v)
	}
	_ = a.ws.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
	if v, _ := expectText(t, a.ws, 5*time.Second); v != tunnel.MsgBound+" 2222222222222222" {
		t.Fatalf("bind answered with %q", v)
	}
	old := <-held // the application holds it, neither reading nor writing
	open(t, ctl, "2222222222222222")
	h.nextAccept()
	<-held
	old.Close()
	errs := ev.closedWith(t, "2222222222222222")
	var dropped *DroppedError
	if !errors.As(errs[0], &dropped) || dropped.Reason != reasonLegLost {
		t.Errorf("the abandoned attempt closed with %v", errs[0])
	}
}

// A bind for an id that already came with an open message (the hub fell
// back first) is refused: the leg closes, and nothing opens twice.
func TestClientLateBindIsRefused(t *testing.T) {
	h := newScriptHub(t)
	c := h.client(t)
	var ev events
	ev.install(c)
	listenEcho(t, c)
	ctl := h.nextCtl()
	leg := keepLeg(t, h, ctl, "1111111111111111")
	open(t, ctl, "2222222222222222")
	h.nextAccept()
	time.Sleep(50 * time.Millisecond)
	_ = leg.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" 2222222222222222"))
	if v, err := expectText(t, leg, 5*time.Second); err == nil {
		t.Fatalf("a late bind was answered with %q", v)
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	n := 0
	for _, id := range ev.opened {
		if id.String() == "2222222222222222" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("connection 2222… opened %d times", n)
	}
}
