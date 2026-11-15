package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// Reusing the serving side's accept legs: tunnel protocol 2,
// docs/PROTOCOL.md §12.
//
// A serving side that registered with protocol 2 gets a secret, its
// session. An accept that brings the session back, also on protocol 2, is
// offered reuse. When the connection on an offered leg ends cleanly, the
// hub says "idle"; a client that answers "idle" keeps the leg, which waits
// in its tunnel's pool. The tunnel's next connection is handed to the leg
// that became idle last, with "bind <id>", answered by "bound <id>"; without
// that answer in time the hub falls back to the open message of protocol 1.

// Timing (§12.5, §12.6, §12.7); variables so tests can shorten them.
var (
	answerIdleWait = 3 * time.Second  // for the client's "idle" after the hub's
	answerBindWait = 2 * time.Second  // for "bound" after "bind"
	staleIdleLeg   = 15 * time.Second // an idle leg silent this long is not bound
)

const maxReuseIdleSec = 3600

// reuseSettings are the hub's limits on idle legs. MinIdle, MaxIdle and
// Idle apply to each tunnel; the caps to each tenant and to the hub.
type reuseSettings struct {
	Enabled   bool `json:"enabled"`
	IdleSec   int  `json:"idleSeconds"` // an idle leg past this is closed, unless MinIdle keeps it
	MinIdle   int  `json:"minIdle"`     // idle legs kept past IdleSec; never opened to fill
	MaxIdle   int  `json:"maxIdle"`     // idle legs a tunnel holds at most
	TenantCap int  `json:"tenantCap"`
	HubCap    int  `json:"hubCap"`
}

var defaultReuse = reuseSettings{Enabled: true, IdleSec: 60, MinIdle: 3, MaxIdle: 10, TenantCap: 256, HubCap: 4096}

// check reports what is wrong with s, if anything.
func (s reuseSettings) check() string {
	switch {
	case s.IdleSec < 1 || s.IdleSec > maxReuseIdleSec:
		return "the idle limit must be from 1 to 3600 seconds"
	case s.MaxIdle < 0 || s.MaxIdle > 1024:
		return "max idle must be from 0 to 1024"
	case s.MinIdle < 0 || s.MinIdle > s.MaxIdle:
		return "min idle must be from 0 to max idle"
	case s.TenantCap < 0 || s.HubCap < 0:
		return "the caps must not be negative"
	}
	return ""
}

// wordReuse overrides the hub's per-tunnel limits for one word; nil fields
// keep the hub's.
type wordReuse struct {
	IdleSec *int `json:"idleSeconds,omitempty"`
	MinIdle *int `json:"minIdle,omitempty"`
	MaxIdle *int `json:"maxIdle,omitempty"`
}

// relayLeg is one serving-side accept leg that was offered reuse, across
// the connections it carries.
type relayLeg struct {
	id      int    // per tunnel, for the console
	addr    string // the serving side, as the hub sees it
	carried int    // connections it has carried, the current one included
}

// idleLeg is a leg in its tunnel's pool.
type idleLeg struct {
	leg      *relayLeg
	conn     *tunnel.Conn
	since    time.Time
	timer    *time.Timer
	stopPing func()
	binding  atomic.Pointer[string] // the id sent with "bind"
	bound    chan struct{}          // "bound <that id>" arrived; the reader has stopped
	dead     chan struct{}          // the reader ended: the leg is gone
}

// legView is how the console sees a leg.
type legView struct {
	Leg     int `json:"leg"`
	Carried int `json:"carried"`
}

// idleSlots counts the idle legs of each tenant and of the hub.
type idleSlots struct {
	mu       sync.Mutex
	total    int
	byTenant map[string]int
}

func (s *idleSlots) take(tenant string, r reuseSettings) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant == nil {
		s.byTenant = map[string]int{}
	}
	if s.total >= r.HubCap || s.byTenant[tenant] >= r.TenantCap {
		return false
	}
	s.total++
	s.byTenant[tenant]++
	return true
}

func (s *idleSlots) release(tenant string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.byTenant[tenant]--; s.byTenant[tenant] <= 0 {
		delete(s.byTenant, tenant)
	}
}

// isUpgrade reports whether r is a WebSocket handshake that Upgrade would
// answer with a 101; the headers of protocol 2 go out with that 101 only,
// never with a refusal (§12.3).
func isUpgrade(r *http.Request) bool {
	return tunnel.HeaderHasToken(r.Header, "Connection", "upgrade") &&
		tunnel.HeaderHasToken(r.Header, "Upgrade", "websocket") &&
		r.Header.Get("Sec-WebSocket-Version") == "13" && r.Header.Get("Sec-WebSocket-Key") != ""
}

// newSession is a registration's secret.
func newSession() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}

// reuseFor is the effective limits for tunnel t: the hub's, with t's
// word's overrides.
func (h *tunnelHub) reuseFor(t *relayTunnel) reuseSettings {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.reuse
	if res := h.reserved[t.key]; res != nil && res.Reuse != nil {
		if v := res.Reuse.IdleSec; v != nil {
			r.IdleSec = *v
		}
		if v := res.Reuse.MaxIdle; v != nil {
			r.MaxIdle = *v
		}
		if v := res.Reuse.MinIdle; v != nil {
			r.MinIdle = min(*v, r.MaxIdle)
		}
	}
	return r
}

// offerReuse decides whether the accept r for tunnel t is offered reuse,
// and if so sets the offer on w. Only a request that negotiated protocol 2
// and brings the registration's session gets one; anyone else, the
// connecting side with its own connection's id included, gets a plain
// protocol 1 leg.
func (h *tunnelHub) offerReuse(w http.ResponseWriter, r *http.Request, t *relayTunnel) bool {
	if chosenProto(w) < 2 || t.session == nil || !isUpgrade(r) {
		return false
	}
	given, err := hex.DecodeString(r.Header.Get(tunnel.HeaderSession))
	if err != nil || subtle.ConstantTimeCompare(given, t.session) != 1 {
		return false
	}
	rs := h.reuseFor(t)
	if !rs.Enabled || rs.MaxIdle == 0 {
		return false
	}
	w.Header().Set(tunnel.HeaderKeepAlive, strconv.Itoa(rs.IdleSec))
	return true
}

// newLeg numbers a leg that was offered reuse.
func (t *relayTunnel) newLeg(addr string) *relayLeg {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextLeg++
	return &relayLeg{id: t.nextLeg, addr: addr, carried: 1}
}

// reusableUpstream is the serving side's leg of a connection whose leg was
// offered reuse. servePipe closes it when the connection is over; then,
// instead of closing at once, it decides whether the connection finished
// cleanly and, if so, offers the leg back (§12.5).
type reusableUpstream struct {
	*tunnel.Stream
	h      *tunnelHub
	t      *relayTunnel
	leg    *relayLeg
	client *tunnel.Stream // the connecting side's leg of the same connection
	pipeID uint64         // the connection's pipe, for the flow log
	once   sync.Once
}

// Read passes a failure the serving side reports on to the connecting side
// at once. A plain leg passes it on as a half-close first, and the reason
// only when the connection ends (§8.3); on a reused leg the serving side
// answers "bound" before it dials its target, so it is often the only way
// the connecting side hears why.
func (u *reusableUpstream) Read(p []byte) (int, error) {
	n, err := u.Stream.Read(p)
	var remote *tunnel.RemoteError
	if errors.As(err, &remote) {
		reason := cleanHeader(remote.Reason) // as for X-PF-Tunnel-Error (§12.7)
		// Nothing came from the serving side yet: it refused the connection
		// after taking it, which counts as a failure, like a refusal at
		// accept.
		if pp := pipes.get(u.pipeID); pp != nil && pp.down.written.Load() == 0 {
			pp.failReason.CompareAndSwap(nil, &reason)
			u.t.stats.failed.Add(1)
		}
		u.client.Fail(reason)
	}
	return n, err
}

// Close decides at once whether the connection finished cleanly, while
// both legs are as the pipe left them: servePipe closes the connecting leg
// right after this. The rest, which waits on the client, goes on its own.
func (u *reusableUpstream) Close() error {
	u.once.Do(func() {
		// An interrupted pipe (a reset, the tunnel ending) is never clean,
		// whichever of its legs closes first.
		interrupted := false
		if pp := pipes.get(u.pipeID); pp != nil {
			interrupted = pp.interrupted.Load()
		}
		clean := !interrupted && u.Stream.Clean() && u.client.Clean()
		go u.finish(clean)
	})
	return nil
}

func (u *reusableUpstream) finish(clean bool) {
	s := u.Stream
	if !clean {
		if s.HalfClosed() && s.WroteEOF() {
			// Both half-closes went by on this leg, but the connection
			// failed elsewhere: say so, rather than finish it as clean.
			reason := ""
			if s.CloseReason != nil {
				reason = s.CloseReason()
			}
			if reason == "" {
				reason = "the connection failed on the connecting side"
			}
			s.Fail(reason)
			return
		}
		_ = s.Close()
		return
	}
	// Bounded like any control write: a serving side that stopped reading
	// must not hold this goroutine and its socket (§12.5).
	s.Leg().SetTimeouts(tunnel.LinkSilence(), tunnel.WriteTimeout)
	if s.SendIdle() != nil {
		_ = s.Close()
		return
	}
	if idle, _ := s.AwaitIdle(answerIdleWait); !idle {
		_ = s.Close() // the client closed instead, or said nothing in time
		return
	}
	u.h.park(u.t, s.Detach(), u.leg)
}

// park puts an idle leg in its tunnel's pool, or closes it if the pool or
// a cap is full, or the registration it belongs to has ended.
func (h *tunnelHub) park(t *relayTunnel, conn *tunnel.Conn, leg *relayLeg) {
	rs := h.reuseFor(t)
	il := &idleLeg{leg: leg, conn: conn, since: time.Now(), bound: make(chan struct{}, 1), dead: make(chan struct{})}
	t.mu.Lock()
	if t.closed || !rs.Enabled || len(t.pool) >= rs.MaxIdle || !h.slots.take(t.owner, rs) {
		t.mu.Unlock()
		_ = conn.Close()
		return
	}
	t.pool = append(t.pool, il)
	il.timer = time.AfterFunc(time.Duration(rs.IdleSec)*time.Second, func() { h.expire(t, il) })
	conn.SetTimeouts(tunnel.LinkSilence(), tunnel.WriteTimeout)
	il.stopPing = conn.KeepAlive(tunnel.PingEvery())
	t.mu.Unlock()
	go h.readIdle(t, il)
	changes.notify()
}

// readIdle reads an idle leg until it is bound, or ends.
func (h *tunnelHub) readIdle(t *relayTunnel, il *idleLeg) {
	for {
		op, payload, err := il.conn.Next(tunnel.MaxSmallFrame)
		if err == nil && op == tunnel.OpText {
			msg := string(payload)
			if id, ok := strings.CutPrefix(msg, tunnel.MsgBound+" "); ok {
				if want := il.binding.Load(); want != nil && id == *want {
					il.bound <- struct{}{}
					return // the binder takes the leg over
				}
			} else if !knownLegFrame(msg) {
				continue // unknown text is ignored, as on any stream (§8.1)
			}
		}
		// A close, a dead link, data, or a known frame in the wrong state
		// (a violation, §12.4).
		h.unpool(t, il)
		il.stopPing()
		_ = il.conn.Close()
		close(il.dead)
		return
	}
}

// unpool takes il out of the pool, if it is still there.
func (h *tunnelHub) unpool(t *relayTunnel, il *idleLeg) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, x := range t.pool {
		if x == il {
			t.pool = append(t.pool[:i], t.pool[i+1:]...)
			il.timer.Stop()
			h.slots.release(t.owner)
			changes.notify()
			return true
		}
	}
	return false
}

// expire closes an idle leg past the idle limit, unless it is one of the
// MinIdle that became idle last.
func (h *tunnelHub) expire(t *relayTunnel, il *idleLeg) {
	rs := h.reuseFor(t)
	t.mu.Lock()
	for i, x := range t.pool {
		if x != il {
			continue
		}
		if newer := len(t.pool) - 1 - i; rs.Enabled && newer < rs.MinIdle {
			il.timer.Reset(time.Duration(rs.IdleSec) * time.Second)
			t.mu.Unlock()
			return
		}
		t.pool = append(t.pool[:i], t.pool[i+1:]...)
		h.slots.release(t.owner)
		t.mu.Unlock()
		_ = il.conn.Close() // the reader ends
		changes.notify()
		return
	}
	t.mu.Unlock()
}

// takeIdle takes the leg that became idle last and was heard from lately,
// closing stale ones on the way.
func (h *tunnelHub) takeIdle(t *relayTunnel) *idleLeg {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.pool) > 0 {
		il := t.pool[len(t.pool)-1]
		t.pool = t.pool[:len(t.pool)-1]
		il.timer.Stop()
		h.slots.release(t.owner)
		heard := il.conn.Heard()
		if heard.IsZero() || time.Since(heard) <= staleIdleLeg {
			return il
		}
		_ = il.conn.Close() // stale: probably dead
	}
	return nil
}

// bind hands connection id to an idle leg of t (§12.7). It returns the leg's
// new stream, or nil when there is no idle leg or the one taken did not
// answer; the caller then falls back to the open message.
func (h *tunnelHub) bind(t *relayTunnel, id string) (*tunnel.Stream, *relayLeg) {
	il := h.takeIdle(t)
	if il == nil {
		return nil, nil
	}
	il.binding.Store(&id)
	if il.conn.WriteFrame(tunnel.OpText, []byte(tunnel.MsgBind+" "+id)) != nil {
		_ = il.conn.Close()
		return nil, nil
	}
	timer := time.NewTimer(answerBindWait)
	defer timer.Stop()
	select {
	case <-il.bound:
	case <-il.dead:
		return nil, nil
	case <-timer.C:
		_ = il.conn.Close() // never used again; a late "bound" goes nowhere
		return nil, nil
	case <-t.done:
		_ = il.conn.Close()
		return nil, nil
	}
	il.stopPing()
	s := tunnel.NewStream(il.conn)
	s.SetReusable(true)
	s.SetRemote(il.leg.addr)
	t.mu.Lock()
	il.leg.carried++
	t.mu.Unlock()
	t.reused.Add(1)
	return s, il.leg
}

// closePool closes every idle leg of a tunnel that is closing.
func (h *tunnelHub) closePool(t *relayTunnel) {
	t.mu.Lock()
	pool := t.pool
	t.pool = nil
	for _, il := range pool {
		il.timer.Stop()
		h.slots.release(t.owner)
	}
	t.mu.Unlock()
	for _, il := range pool {
		_ = il.conn.Close()
	}
}

// idleSnapshot is one idle leg in the console.
type idleSnapshot struct {
	Leg       int    `json:"leg"`
	ServeAddr string `json:"serveAddr"`
	Since     int64  `json:"since"`   // idle since, unix milliseconds
	Carried   int    `json:"carried"` // connections it carried
	Kept      bool   `json:"kept"`    // past the idle limit, kept by min idle
}

// legNumber is the leg a console request names.
func legNumber(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0
}

// closeIdleLeg closes idle leg n of the tunnel of reservation id, for the
// console.
func (h *tunnelHub) closeIdleLeg(id, n int) error {
	h.mu.Lock()
	var t *relayTunnel
	for key, res := range h.reserved {
		if res.id == id {
			t = h.tunnels[key]
		}
	}
	h.mu.Unlock()
	if t == nil {
		return errNoWord
	}
	t.mu.Lock()
	var il *idleLeg
	for _, x := range t.pool {
		if x.leg.id == n {
			il = x
		}
	}
	t.mu.Unlock()
	if il == nil || !h.unpool(t, il) {
		return errNoLeg
	}
	_ = il.conn.Close()
	return nil
}

// badSetting is a setting the console sent that cannot be used.
type badSetting struct{ msg string }

func (e *badSetting) Error() string { return e.msg }

// setReuse changes the hub's limits on reusing legs and saves them. Idle
// legs over the new limits, or all of them when reuse is turned off, are
// closed.
func (h *tunnelHub) setReuse(r reuseSettings) error {
	if msg := r.check(); msg != "" {
		return &badSetting{msg}
	}
	h.mu.Lock()
	if h.reuse == r {
		h.mu.Unlock()
		return nil
	}
	if h.persistReuse == nil {
		h.mu.Unlock()
		return errSettingsFixed
	}
	if err := h.persistReuse(r); err != nil {
		h.mu.Unlock()
		return err
	}
	h.reuse = r
	tunnels := make([]*relayTunnel, 0, len(h.tunnels))
	for _, t := range h.tunnels {
		tunnels = append(tunnels, t)
	}
	h.mu.Unlock()
	for _, t := range tunnels {
		h.trimPool(t)
		h.retime(t)
	}
	h.trimCaps(tunnels, r)
	log.Printf("relay: reuse of accept legs changed from the console: enabled=%v, idle %ds, min %d, max %d, caps %d per tenant, %d in all",
		r.Enabled, r.IdleSec, r.MinIdle, r.MaxIdle, r.TenantCap, r.HubCap)
	changes.notify()
	return nil
}

// setWordReuse sets, or with nil clears, the limits of the word of
// reservation id. They are kept with the word's binding.
func (h *tunnelHub) setWordReuse(id int, wr *wordReuse) error {
	if wr != nil {
		r := defaultReuse
		if wr.IdleSec != nil {
			r.IdleSec = *wr.IdleSec
		}
		if wr.MaxIdle != nil {
			r.MaxIdle = *wr.MaxIdle
		}
		r.MinIdle = 0
		if wr.MinIdle != nil {
			r.MinIdle = *wr.MinIdle
			if wr.MaxIdle == nil {
				r.MaxIdle = max(r.MaxIdle, r.MinIdle)
			}
		}
		if msg := r.check(); msg != "" {
			return &badSetting{msg}
		}
		if wr.IdleSec == nil && wr.MinIdle == nil && wr.MaxIdle == nil {
			wr = nil
		}
	}
	h.mu.Lock()
	var t *relayTunnel
	found := false
	for key, res := range h.reserved {
		if res.id == id {
			found, t = true, h.tunnels[key]
			res.Reuse = wr
			h.saveLocked()
		}
	}
	h.mu.Unlock()
	if !found {
		return errNoWord
	}
	if t != nil {
		h.trimPool(t)
	}
	changes.notify()
	return nil
}

// trimPool closes the idle legs a tunnel holds beyond its limits now:
// all of them when reuse is off, the oldest beyond max idle otherwise.
func (h *tunnelHub) trimPool(t *relayTunnel) {
	rs := h.reuseFor(t)
	keep := rs.MaxIdle
	if !rs.Enabled {
		keep = 0
	}
	t.mu.Lock()
	var extra []*idleLeg
	for len(t.pool) > keep {
		il := t.pool[0]
		t.pool = t.pool[1:]
		il.timer.Stop()
		h.slots.release(t.owner)
		extra = append(extra, il)
	}
	t.mu.Unlock()
	for _, il := range extra {
		_ = il.conn.Close()
	}
}

// retime moves each idle leg's expiry to the tunnel's idle limit now,
// counted from when the leg became idle.
func (h *tunnelHub) retime(t *relayTunnel) {
	limit := time.Duration(h.reuseFor(t).IdleSec) * time.Second
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, il := range t.pool {
		il.timer.Reset(max(limit-time.Since(il.since), time.Millisecond))
	}
}

// trimCaps closes idle legs, oldest first, until every tenant and the hub
// are within r's caps. The caps win over min idle (§12.6).
func (h *tunnelHub) trimCaps(tunnels []*relayTunnel, r reuseSettings) {
	type entry struct {
		t  *relayTunnel
		il *idleLeg
	}
	var all []entry
	for _, t := range tunnels {
		t.mu.Lock()
		for _, il := range t.pool {
			all = append(all, entry{t, il})
		}
		t.mu.Unlock()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].il.since.Before(all[j].il.since) })
	total, byTenant := len(all), map[string]int{}
	for _, e := range all {
		byTenant[e.t.owner]++
	}
	for _, e := range all {
		if total <= r.HubCap && byTenant[e.t.owner] <= r.TenantCap {
			continue
		}
		if h.unpool(e.t, e.il) {
			_ = e.il.conn.Close()
			total--
			byTenant[e.t.owner]--
		}
	}
}

// handleWordReuse sets a word's own limits on idle legs; a body of {}, or
// with every field null, goes back to the hub's.
func (s *consoleServer) handleWordReuse(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	var wr wordReuse
	if err != nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&wr) != nil {
		writeError(w, http.StatusBadRequest, "use /relay/{id}/reuse with {\"idleSeconds\":…,\"minIdle\":…,\"maxIdle\":…}")
		return
	}
	if s.tunnels == nil {
		writeError(w, http.StatusNotFound, "this server has no relay hub")
		return
	}
	var bad *badSetting
	switch err := s.tunnels.setWordReuse(id, &wr); {
	case err == nil:
		writeJSON(w, s.tunnels.snapshot())
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, bad.msg)
	default:
		writeError(w, http.StatusNotFound, "no such word")
	}
}

// handleCloseIdleLeg closes one idle leg of a word's tunnel.
func (s *consoleServer) handleCloseIdleLeg(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	leg, ok := legNumber(r.PathValue("leg"))
	if err != nil || !ok {
		writeError(w, http.StatusBadRequest, "use /relay/{id}/legs/{leg}/close")
		return
	}
	if s.tunnels == nil || s.tunnels.closeIdleLeg(id, leg) != nil {
		writeError(w, http.StatusNotFound, "no such idle leg")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// knownLegFrame reports whether msg is one of the text frames of streams and
// reused legs (§8.1, §12): such a frame where it does not belong is a
// violation, while any other text is ignored.
func knownLegFrame(msg string) bool {
	switch {
	case msg == "eof", msg == tunnel.MsgIdle, msg == tunnel.MsgBind, msg == tunnel.MsgBound,
		strings.HasPrefix(msg, "err:"), strings.HasPrefix(msg, tunnel.MsgBind+" "), strings.HasPrefix(msg, tunnel.MsgBound+" "):
		return true
	}
	return false
}
