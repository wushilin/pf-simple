package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/wushilin/pf-simple/internal/quictun"
	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The relay hub over QUIC: protocol 3 (docs/PROTOCOL.md §13).
//
// A QUIC connection carries requests, one per stream: serve, connect,
// check. They go through the same checks as the WebSocket endpoints,
// guard included, by way of an http.Request made from the request message,
// so the two transports cannot drift apart. A connection's two legs may be
// on different transports: the hub pipes tunnel.Streams either way.

// quicSettings is [tunnel.quic], also changed in the console.
type quicSettings struct {
	Enabled        bool   `json:"enabled"`
	Listen         string `json:"listen"`
	AdvertiseHost  string `json:"advertiseHost"`
	AdvertisePort  int    `json:"advertisePort"`
	MaxConnections int    `json:"maxConnections"`
	MaxBufferedMiB int    `json:"maxBufferedMiB"`
}

var defaultQUIC = quicSettings{Listen: ":443", MaxConnections: 10000, MaxBufferedMiB: 1024}

func (s quicSettings) check() string {
	switch {
	case s.Enabled && strings.TrimSpace(s.Listen) == "":
		return "give the QUIC listener a UDP address, such as :443"
	case s.AdvertisePort < 0 || s.AdvertisePort > 65535:
		return "the advertised port must be 1 to 65535"
	case strings.ContainsAny(s.AdvertiseHost, "[]/ "):
		return "the advertised host is a name or an address, without brackets or a port"
	case s.MaxConnections < 1:
		return "max connections must be at least 1"
	case s.MaxBufferedMiB < 1:
		return "max buffered must be at least 1 MiB"
	}
	if s.Listen != "" {
		if _, _, err := net.SplitHostPort(s.Listen); err != nil {
			return "the QUIC listen address must be host:port or :port"
		}
	}
	return ""
}

// Limits of §13.8; variables so tests can lower them.
var (
	quicConnsPerAddr    = 64
	quicStreamsPerAddr  = 4096
	quicRefusalsPerConn = 5
	quicUnusedClose     = 5 * time.Minute
	quicCertOverlap     = 10 * time.Minute
	// A certificate with less than quicCertRenew left is replaced; the
	// hub looks every quicCertCheck.
	quicCertRenew = 15 * 24 * time.Hour
	quicCertCheck = time.Hour
	streamBudget  = int64(128 << 10) // what one open stream may make the hub hold
)

// quicHub is the hub's QUIC listener and its connections.
type quicHub struct {
	h        *tunnelHub
	certPath string // where the certificate is kept; "" keeps it in memory
	keyPath  string
	persist  func(quicSettings) error
	// advertiseFor, when set, gives the port discovery answers for a run
	// of op ("serve", "connect"), so that a test can route each side
	// through its own link. Tests only.
	advertiseFor func(op string) int

	mu        sync.Mutex
	set       quicSettings
	cert      *tls.Certificate
	oldFP     string // the certificate replaced last, still announced until oldUntil
	oldUntil  time.Time
	pc        net.PacketConn
	stopRenew chan struct{}
	tr        *quic.Transport
	ln        *quic.Listener
	conns     map[*quic.Conn]*quicConn
	perAddr   map[string]int
	streams   map[string]int // open client streams per address
	total     atomic.Int64   // open client streams in all
	listenErr string
}

func newQUICHub(h *tunnelHub, configPath string) *quicHub {
	q := &quicHub{h: h, set: defaultQUIC, conns: map[*quic.Conn]*quicConn{}, perAddr: map[string]int{}, streams: map[string]int{}}
	if configPath != "" {
		stem := strings.TrimSuffix(configPath, fileExt(configPath))
		q.certPath, q.keyPath = stem+".quic-cert.pem", stem+".quic-key.pem"
	}
	h.quic = q
	return q
}

func fileExt(p string) string {
	if i := strings.LastIndexByte(p, '.'); i > strings.LastIndexByte(p, '/') {
		return p[i:]
	}
	return ""
}

// loadCert loads the kept certificate, or makes one. Under q.mu.
func (q *quicHub) loadCertLocked() error {
	if q.cert != nil {
		return nil
	}
	if q.certPath != "" {
		if c, err := tls.LoadX509KeyPair(q.certPath, q.keyPath); err == nil && !dueForRenewal(&c) {
			q.cert = &c
			return nil
		}
	}
	return q.newCertLocked()
}

// dueForRenewal reports whether c has less than quicCertRenew left.
func dueForRenewal(c *tls.Certificate) bool {
	leaf := leafOf(c)
	return leaf == nil || time.Until(leaf.NotAfter) < quicCertRenew
}

// renew replaces the certificate whenever it is due, until stop is closed.
func (q *quicHub) renew(stop <-chan struct{}) {
	t := time.NewTicker(quicCertCheck)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		q.renewIfDue()
	}
}

// renewIfDue replaces the certificate if it is due.
func (q *quicHub) renewIfDue() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.cert == nil || !dueForRenewal(q.cert) {
		return
	}
	if err := q.newCertLocked(); err != nil {
		log.Printf("relay: cannot renew the QUIC certificate: %v", err)
		return
	}
	log.Printf("relay: renewed the QUIC certificate: %s, valid until %s",
		quictun.Fingerprint(q.cert.Certificate[0]), leafOf(q.cert).NotAfter.Format(time.DateOnly))
}

func (q *quicHub) newCertLocked() error {
	certPEM, keyPEM, err := quictun.NewCertificate(q.set.AdvertiseHost)
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if q.certPath != "" {
		if err := os.WriteFile(q.keyPath, keyPEM, 0o600); err != nil {
			return fmt.Errorf("cannot keep the QUIC certificate's key: %w", err)
		}
		if err := os.WriteFile(q.certPath, certPEM, 0o644); err != nil {
			return fmt.Errorf("cannot keep the QUIC certificate: %w", err)
		}
	}
	if q.cert != nil {
		q.oldFP, q.oldUntil = quictun.Fingerprint(q.cert.Certificate[0]), time.Now().Add(quicCertOverlap)
	}
	q.cert = &c
	return nil
}

// replaceCert makes a new certificate (§13.10). New handshakes get it at
// once; discovery announces the old one too for a while.
func (q *quicHub) replaceCert() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.newCertLocked()
}

// fingerprints are what discovery announces. Under q.mu.
func (q *quicHub) fingerprintsLocked() []string {
	fps := []string{quictun.Fingerprint(q.cert.Certificate[0])}
	if q.oldFP != "" && time.Now().Before(q.oldUntil) {
		fps = append(fps, q.oldFP)
	}
	return fps
}

// discovery is what GET /quic answers, and false when the listener is off
// or has no advertised host.
func (q *quicHub) discovery() (quictun.Discovery, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ln == nil || q.set.AdvertiseHost == "" || q.cert == nil {
		return quictun.Discovery{}, false
	}
	port := q.set.AdvertisePort
	if port == 0 {
		_, p, _ := net.SplitHostPort(q.pc.LocalAddr().String())
		port, _ = strconv.Atoi(p)
	}
	return quictun.Discovery{Host: q.set.AdvertiseHost, Port: port, Fingerprints: q.fingerprintsLocked()}, true
}

// discoveryFor is discovery as the client of a run for op sees it: tests
// may send each side its own way to the listener (advertiseFor).
func (q *quicHub) discoveryFor(op string) (quictun.Discovery, bool) {
	d, ok := q.discovery()
	if ok && q.advertiseFor != nil {
		if port := q.advertiseFor(op); port != 0 {
			d.Port = port
		}
	}
	return d, ok
}

// apply takes new settings: it starts, restarts or stops the listener as
// they ask, and keeps them.
func (q *quicHub) apply(s quicSettings) error {
	if msg := s.check(); msg != "" {
		return &badSetting{msg}
	}
	q.mu.Lock()
	old := q.set
	restart := s.Enabled != old.Enabled || s.Listen != old.Listen || (s.Enabled && q.ln == nil)
	q.set = s
	q.mu.Unlock()
	if restart {
		q.stop()
		if s.Enabled {
			if err := q.start(); err != nil {
				q.mu.Lock()
				q.set = old
				q.mu.Unlock()
				return err
			}
		}
	}
	if q.persist != nil {
		if err := q.persist(s); err != nil {
			return err
		}
	}
	changes.notify()
	return nil
}

// start opens the listener for the current settings.
func (q *quicHub) start() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.ln != nil || !q.set.Enabled {
		return nil
	}
	if err := q.loadCertLocked(); err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", q.set.Listen)
	if err != nil {
		q.listenErr = err.Error()
		return fmt.Errorf("QUIC listen on %s: %w", q.set.Listen, err)
	}
	tr := &quic.Transport{Conn: pc, VerifySourceAddress: q.verifySource}
	tlsConf := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			q.mu.Lock()
			defer q.mu.Unlock()
			return q.cert, nil
		},
		NextProtos:             []string{quictun.ALPN},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	conf := quictun.Config()
	conf.GetConfigForClient = q.admitHandshake
	conf.AllowConnectionWindowIncrease = q.allowWindow
	ln, err := tr.Listen(tlsConf, conf)
	if err != nil {
		_ = pc.Close()
		return err
	}
	q.pc, q.tr, q.ln, q.listenErr = pc, tr, ln, ""
	q.stopRenew = make(chan struct{})
	go q.accept(ln)
	go q.renew(q.stopRenew)
	log.Printf("relay: QUIC listener on udp %s, certificate %s", pc.LocalAddr(), quictun.Fingerprint(q.cert.Certificate[0]))
	return nil
}

// stop closes the listener and every QUIC connection (going-away).
func (q *quicHub) stop() {
	q.mu.Lock()
	ln, tr, pc := q.ln, q.tr, q.pc
	q.ln, q.tr, q.pc = nil, nil, nil
	if q.stopRenew != nil {
		close(q.stopRenew)
		q.stopRenew = nil
	}
	conns := make([]*quic.Conn, 0, len(q.conns))
	for c := range q.conns {
		conns = append(conns, c)
	}
	q.mu.Unlock()
	if ln == nil {
		return
	}
	for _, c := range conns {
		_ = c.CloseWithError(quictun.CodeGoingAway, "the hub's QUIC listener is stopping")
	}
	_ = ln.Close()
	_ = tr.Close()
	_ = pc.Close()
}

// addrKey is the address refusals and limits are counted against, as
// sourceKey does for HTTPS: IPv6 by /64.
func addrKey(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return ip.String()
}

// verifySource asks for a Retry when an address already has connections,
// or the hub is busy, so spoofed handshakes cannot take its slots (§13.8).
func (q *quicHub) verifySource(a net.Addr) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.perAddr[addrKey(a)] >= 8 || len(q.conns) > q.set.MaxConnections/2
}

// admitHandshake refuses a handshake over the connection limits; the client
// sees CONNECTION_REFUSED (§13.7).
func (q *quicHub) admitHandshake(info *quic.ClientInfo) (*quic.Config, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.conns) >= q.set.MaxConnections || q.perAddr[addrKey(info.RemoteAddr)] >= quicConnsPerAddr {
		return nil, errors.New("too many QUIC connections")
	}
	return nil, nil
}

// allowWindow lets a connection's window grow only once it has made a
// successful request (§13.3).
func (q *quicHub) allowWindow(c *quic.Conn, _ uint64) bool {
	q.mu.Lock()
	qc := q.conns[c]
	q.mu.Unlock()
	return qc != nil && qc.authed.Load()
}

func (q *quicHub) accept(ln *quic.Listener) {
	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		qc := &quicConn{q: q, conn: c, key: addrKey(c.RemoteAddr()), addr: c.RemoteAddr().String(), last: time.Now()}
		q.mu.Lock()
		if q.ln != ln || len(q.conns) >= q.set.MaxConnections || q.perAddr[qc.key] >= quicConnsPerAddr {
			q.mu.Unlock()
			_ = c.CloseWithError(quictun.CodeLimit, "too many QUIC connections")
			continue
		}
		q.conns[c] = qc
		q.perAddr[qc.key]++
		q.mu.Unlock()
		go qc.run()
	}
}

// stream counts an open client stream of key against the limits, and
// reports false when it may not open.
func (q *quicHub) stream(key string, delta int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if delta > 0 {
		limit := int64(q.set.MaxBufferedMiB) << 20 / streamBudget
		if q.streams[key] >= quicStreamsPerAddr || q.total.Load() >= limit {
			return false
		}
	}
	q.streams[key] += delta
	if q.streams[key] <= 0 {
		delete(q.streams, key)
	}
	q.total.Add(int64(delta))
	return true
}

// ---------- one QUIC connection ----------

type quicConn struct {
	q    *quicHub
	conn *quic.Conn
	key  string // addrKey of the address it was opened from
	addr string

	authed  atomic.Bool // it has made a successful request
	preAuth sync.Mutex  // before that, its requests are read one at a time

	mu       sync.Mutex
	busy     int         // streams being handled, registrations included
	last     time.Time   // when busy last fell to 0
	refusals []time.Time // refused requests in the last minute
}

func (qc *quicConn) run() {
	defer func() {
		qc.q.mu.Lock()
		delete(qc.q.conns, qc.conn)
		if qc.q.perAddr[qc.key]--; qc.q.perAddr[qc.key] <= 0 {
			delete(qc.q.perAddr, qc.key)
		}
		qc.q.mu.Unlock()
	}()
	// No successful request in time: closed (§13.8).
	first := time.AfterFunc(quictun.RequestWait, func() {
		if !qc.authed.Load() {
			_ = qc.conn.CloseWithError(quictun.CodeRequestTimeout, "no request in time")
		}
	})
	defer first.Stop()
	go qc.closeWhenUnused()
	for {
		s, err := qc.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		qc.setBusy(1)
		go func() {
			defer qc.setBusy(-1)
			qc.handle(s)
		}()
	}
}

func (qc *quicConn) setBusy(d int) {
	qc.mu.Lock()
	qc.busy += d
	if qc.busy == 0 {
		qc.last = time.Now()
	}
	qc.mu.Unlock()
}

// closeWhenUnused closes the connection once it has held nothing for a
// while: routine, the client opens a new one when it needs one.
func (qc *quicConn) closeWhenUnused() {
	t := time.NewTicker(min(quicUnusedClose/4, 30*time.Second))
	defer t.Stop()
	for {
		select {
		case <-qc.conn.Context().Done():
			return
		case <-t.C:
			qc.mu.Lock()
			unused := qc.busy == 0 && time.Since(qc.last) >= quicUnusedClose
			qc.mu.Unlock()
			if unused {
				_ = qc.conn.CloseWithError(quictun.CodeNone, "unused")
				return
			}
		}
	}
}

// refused counts a refused request on this connection.
func (qc *quicConn) refused() {
	qc.mu.Lock()
	qc.refusals = append(qc.recentLocked(), time.Now())
	qc.mu.Unlock()
}

func (qc *quicConn) recentLocked() []time.Time {
	keep := qc.refusals[:0]
	for _, t := range qc.refusals {
		if time.Since(t) < guessWindow {
			keep = append(keep, t)
		}
	}
	return keep
}

// limited reports whether this connection has had too many refusals of
// late (§13.8).
func (qc *quicConn) limited() bool {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	qc.refusals = qc.recentLocked()
	return len(qc.refusals) >= quicRefusalsPerConn
}

// recorder captures what a hub handler answers.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

// handle serves one client stream: its request, and then whatever the
// request carries.
func (qc *quicConn) handle(s *quic.Stream) {
	unlock := func() {}
	if !qc.authed.Load() {
		qc.preAuth.Lock()
		var once sync.Once
		unlock = func() { once.Do(qc.preAuth.Unlock) }
		defer unlock()
	}
	_ = s.SetReadDeadline(time.Now().Add(quictun.RequestWait))
	raw, err := quictun.ReadRaw(s)
	_ = s.SetReadDeadline(time.Time{})
	if err != nil {
		code := quic.StreamErrorCode(quictun.CodeProtocol)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = quictun.CodeRequestTimeout
		}
		s.CancelWrite(code)
		s.CancelRead(code)
		return
	}
	answer := func(a quictun.Answer) {
		_ = s.SetWriteDeadline(time.Now().Add(tunnel.WriteTimeout))
		_ = quictun.WriteMessage(s, a)
		_ = s.SetWriteDeadline(time.Time{})
	}
	refuse := func(a quictun.Answer) {
		a.Proto = quictun.Proto
		answer(a)
		quictun.Refuse(s)
	}
	var req quictun.Request
	if json.Unmarshal(raw, &req) != nil {
		refuse(quictun.Answer{Status: http.StatusBadRequest, Error: "the request is not a JSON object of the right shape"})
		return
	}
	min, max, err := tunnel.ParseProtoRange(req.Proto)
	switch {
	case err != nil:
		refuse(quictun.Answer{Status: http.StatusBadRequest, Error: err.Error()})
		return
	case min > quictun.Proto || max < quictun.Proto:
		refuse(quictun.Answer{Status: http.StatusUpgradeRequired,
			Error: fmt.Sprintf("this hub speaks QUIC protocol %d and this client offers %s", quictun.Proto, req.Proto)})
		return
	case req.Op != "serve" && req.Op != "connect" && req.Op != "check":
		refuse(quictun.Answer{Status: http.StatusBadRequest, Error: fmt.Sprintf("unknown op %q", req.Op)})
		return
	case qc.limited():
		refuse(quictun.Answer{Status: http.StatusTooManyRequests, Error: "too many refused requests on this connection; open a new one",
			RetryAfter: int(guessWindow / time.Second), Scope: "connection"})
		return
	}
	if req.Op != "check" {
		if !qc.q.stream(qc.key, 1) {
			refuse(quictun.Answer{Status: http.StatusTooManyRequests, Error: "the hub is carrying too much from your address; try again shortly",
				RetryAfter: 5, Scope: "address"})
			return
		}
		defer qc.q.stream(qc.key, -1)
	}

	r := qc.httpRequest(&req)
	rec := &recorder{header: http.Header{}}
	h := qc.q.h
	var t *relayTunnel
	var sr *serveReg
	switch req.Op {
	case "check":
		h.quicGuard(h.handleCheck)(rec, r)
	case "connect":
		h.quicGuard(func(w http.ResponseWriter, r *http.Request) {
			if t = h.admit(r); t == nil {
				h.deny(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
		})(rec, r)
	case "serve":
		h.quicGuard(func(w http.ResponseWriter, r *http.Request) {
			if sr = h.checkServe(w, r); sr != nil {
				w.WriteHeader(http.StatusOK)
			}
		})(rec, r)
	}
	proto := quictun.Proto
	if rec.status != http.StatusOK && rec.status != http.StatusNoContent {
		if rec.status == http.StatusForbidden || rec.status == http.StatusConflict {
			qc.refused()
		}
		a := quictun.Answer{Status: rec.status, Proto: proto, Error: recordedError(rec)}
		if rec.status == http.StatusTooManyRequests {
			a.RetryAfter, a.Scope = int(guessWindow/time.Second), "address"
		}
		refuse(a)
		return
	}
	qc.authed.Store(true)
	switch req.Op {
	case "check":
		answer(quictun.Answer{Status: http.StatusNoContent, Proto: proto})
		unlock()
		quictun.Finish(s)
	case "connect":
		connID, err := newConnID()
		if err != nil {
			refuse(quictun.Answer{Status: http.StatusInternalServerError, Proto: proto, Error: "internal error"})
			return
		}
		answer(quictun.Answer{Status: http.StatusOK, Proto: proto, Conn: connID})
		unlock()
		client := tunnel.NewStream(tunnel.NewFramed(quictun.NewStreamConn(s, qc.conn)))
		client.SetRemote(qc.addr)
		h.relay(t, connID, client)
	case "serve":
		qc.serve(s, sr, r, proto, answer, unlock)
	}
}

// quicGuard is guard for a request over QUIC: the hub's switch and the
// refusals of the request's address, but none of the WebSocket protocol
// negotiation, which the QUIC request did itself.
func (h *tunnelHub) quicGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		on := h.enabled
		h.mu.Unlock()
		if !on {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if h.guesses.blocked(sourceKey(r)) {
			writeError(w, http.StatusTooManyRequests, "too many refused attempts from your address; try again in a minute")
			return
		}
		next(w, r)
	}
}

// recordedError is the message of a refusal a handler wrote.
func recordedError(rec *recorder) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(rec.body.Bytes(), &e) == nil && e.Error != "" {
		return e.Error
	}
	if rec.status == http.StatusNotFound {
		return "this server does not accept tunnels"
	}
	return http.StatusText(rec.status)
}

// httpRequest makes the request a WebSocket client would have sent, so the
// hub's own checks judge it.
func (qc *quicConn) httpRequest(req *quictun.Request) *http.Request {
	hd := http.Header{}
	set := func(k, v string) {
		if v != "" {
			hd.Set(k, v)
		}
	}
	set(tunnel.HeaderVersion, req.Version)
	set(tunnel.HeaderWord, req.Word)
	set(tunnel.HeaderServe, req.ServeToken)
	set(tunnel.HeaderName, url.QueryEscape(req.Name))
	set(tunnel.HeaderTarget, req.Target)
	set(tunnel.HeaderClientHash, req.ClientTokenSHA256)
	set(tunnel.HeaderClientToken, req.ClientToken)
	return &http.Request{
		Method: http.MethodGet, URL: &url.URL{Path: tunnel.Path + "/" + req.Op}, Header: hd,
		RemoteAddr: qc.addr, TLS: &tls.ConnectionState{},
	}
}

// serve holds a registration over QUIC for as long as its serve stream
// lasts (§13.4).
func (qc *quicConn) serve(s *quic.Stream, sr *serveReg, r *http.Request, proto int, answer func(quictun.Answer), unlock func()) {
	h := qc.q.h
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	reg := hex.EncodeToString(raw[:])
	t := h.newRelayTunnel(sr, r, proto)
	t.qs = &quicServe{qc: qc, s: s, reg: reg, answered: make(chan struct{})}
	answer(quictun.Answer{Status: http.StatusOK, Proto: proto, Reg: reg})
	close(t.qs.answered)
	unlock()
	if !h.install(t, sr, r) {
		t.qs.endWith("closed", "the registration changed while it was being made")
		return
	}
	// Nothing more comes on the serve stream but its end.
	var b [1]byte
	n, _ := s.Read(b[:])
	if n > 0 {
		t.qs.clientGone.Store(true)
		s.CancelWrite(quictun.CodeProtocol)
		s.CancelRead(quictun.CodeProtocol)
		h.drop(t, "the serving side broke the protocol")
		return
	}
	t.qs.clientGone.Store(true)
	h.drop(t, "the serving side disconnected")
}

// quicServe is a registration over QUIC: its serve stream and its id.
type quicServe struct {
	qc         *quicConn
	s          *quic.Stream
	reg        string
	answered   chan struct{} // the 200 went out; no open before it (§13.4)
	clientGone atomic.Bool   // the client ended the serve stream
	once       sync.Once
}

// endCode is the end message's code for why a registration ended.
func endCode(why string) string {
	switch {
	case strings.HasPrefix(why, "served again from"):
		return quictun.EndTakeover
	case why == "its tenant was deleted" || why == "the tenant's serve token was replaced":
		return quictun.EndTenant
	case why == "the relay hub was turned off" || why == "serving without a token was turned off":
		return quictun.EndOff
	case why == "shutting down":
		return quictun.EndShutdown
	}
	return "closed"
}

// end ends the registration's serve stream, saying why unless the client
// ended it.
func (q *quicServe) end(why string) { q.endWith(endCode(why), why) }

func (q *quicServe) endWith(code, why string) {
	q.once.Do(func() {
		if !q.clientGone.Load() {
			_ = q.s.SetWriteDeadline(time.Now().Add(quictun.DeliverWait))
			_ = quictun.WriteMessage(q.s, quictun.End{End: code, Error: why})
		}
		_ = q.s.Close()
		s := q.s
		time.AfterFunc(quictun.DeliverWait, func() { s.CancelRead(quictun.CodeCancelled) })
	})
}

// openQUIC asks a QUIC serving side for its leg of connection id, on a
// stream the hub opens to it (§13.4).
func (h *tunnelHub) openQUIC(t *relayTunnel, id string) (servedLeg, string) {
	q := t.qs
	select {
	case <-q.answered:
	case <-t.done:
		return servedLeg{}, "the tunnel closed"
	}
	select {
	case <-t.done:
		return servedLeg{}, "the tunnel closed"
	default:
	}
	s, err := q.qc.conn.OpenStream()
	if err != nil {
		var limit quic.StreamLimitReachedError
		if errors.As(err, &limit) {
			return servedLeg{}, "the serving side has too many connections open"
		}
		return servedLeg{}, "the serving side is not connected"
	}
	deadline := time.Now().Add(h.openWait)
	_ = s.SetDeadline(deadline)
	if quictun.WriteMessage(s, quictun.Open{Open: id, Reg: q.reg}) != nil {
		s.CancelWrite(quictun.CodeBroken)
		s.CancelRead(quictun.CodeBroken)
		return servedLeg{}, "the serving side is not connected"
	}
	var a quictun.Answer
	err = quictun.ReadMessage(s, &a)
	_ = s.SetDeadline(time.Time{})
	if err != nil {
		code := quic.StreamErrorCode(quictun.CodeProtocol)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = quictun.CodeRequestTimeout
		}
		s.CancelWrite(code)
		s.CancelRead(code)
		return servedLeg{}, "the serving side did not answer"
	}
	if a.Status == http.StatusOK {
		leg := tunnel.NewStream(tunnel.NewFramed(quictun.NewStreamConn(s, q.qc.conn)))
		leg.SetRemote(t.serveAddr)
		return servedLeg{s: leg}, ""
	}
	quictun.Finish(s)
	reason := cleanHeader(a.Error)
	if len(reason) > 128 {
		reason = reason[:128]
	}
	switch {
	case a.Status == http.StatusGone:
		reason = "the tunnel closed"
	case reason == "":
		reason = "the serving side refused the connection"
	}
	return servedLeg{}, reason
}

// transportNote is how the log names a tunnel's transport.
func (t *relayTunnel) transportNote() string {
	if t.qs != nil {
		return ", over QUIC"
	}
	return ""
}

// transport is "quic" or "ws", for the console.
func (t *relayTunnel) transport() string {
	if t.qs != nil {
		return "quic"
	}
	return "ws"
}

// ---------- discovery (§13.2) ----------

// handleQUICDiscovery answers where the QUIC listener is, to a client with
// the credentials of the run it is about to make.
func (h *tunnelHub) handleQUICDiscovery(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get(tunnel.HeaderOp) {
	case "serve":
		token := r.Header.Get(tunnel.HeaderServe)
		h.mu.Lock()
		ok := (token == "" && h.anonymous) || (token != "" && h.tenantOfLocked(token) != nil)
		h.mu.Unlock()
		if !ok {
			h.deny(w, r)
			return
		}
	case "connect":
		if h.admit(r) == nil {
			h.deny(w, r)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "say what the QUIC run is for: "+tunnel.HeaderOp+": serve or connect")
		return
	}
	if h.quic == nil {
		writeError(w, http.StatusNotImplemented, "this hub's QUIC listener is off")
		return
	}
	d, ok := h.quic.discoveryFor(r.Header.Get(tunnel.HeaderOp))
	if !ok {
		writeError(w, http.StatusNotImplemented, "this hub's QUIC listener is off, or has no advertised host")
		return
	}
	writeJSON(w, d)
}

// leafOf parses a certificate's leaf, for the console.
func leafOf(c *tls.Certificate) *x509.Certificate {
	if c == nil || len(c.Certificate) == 0 {
		return nil
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	return leaf
}

// ---------- the console ----------

// quicStatus is the QUIC listener as the console shows it.
type quicStatus struct {
	quicSettings
	// Fixed says the settings cannot be changed here: pf-simple was not
	// started from a config file.
	Fixed bool `json:"fixed"`
	// Listening is the UDP address listened on; empty while off. Error is
	// why it is not listening when it should be.
	Listening string `json:"listening,omitempty"`
	Error     string `json:"error,omitempty"`
	// Fingerprints are what discovery announces, the current certificate
	// first; ValidUntil is when it expires, unix milliseconds.
	Fingerprints []string `json:"fingerprints,omitempty"`
	ValidUntil   int64    `json:"validUntil,omitempty"`
	Connections  int      `json:"connections"`
}

func (q *quicHub) status() *quicStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	st := &quicStatus{quicSettings: q.set, Fixed: q.persist == nil, Error: q.listenErr, Connections: len(q.conns)}
	if q.pc != nil {
		st.Listening = q.pc.LocalAddr().String()
	}
	if q.cert != nil {
		st.Fingerprints = q.fingerprintsLocked()
		if leaf := leafOf(q.cert); leaf != nil {
			st.ValidUntil = leaf.NotAfter.UnixMilli()
		}
	}
	return st
}

// handleQUICCertificate replaces the QUIC listener's certificate now.
func (s *consoleServer) handleQUICCertificate(w http.ResponseWriter, r *http.Request) {
	if s.tunnels == nil || s.tunnels.quic == nil {
		writeError(w, http.StatusNotFound, "this server has no relay hub")
		return
	}
	if err := s.tunnels.quic.replaceCert(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("relay: replaced the QUIC certificate from the console")
	changes.notify()
	writeJSON(w, s.tunnels.snapshot())
}
