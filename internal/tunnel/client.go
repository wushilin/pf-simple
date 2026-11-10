package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// The relay's endpoints and headers. Everything secret travels in headers,
// which reverse proxies do not log by default; URLs they do.
const (
	Path         = "/pf/api/tunnel"   // + "/serve", "/connect", "/accept", "/check"
	HeaderWord   = "X-PF-Tunnel-Word" // the tunnel's secret word
	HeaderServe  = "X-PF-Serve-Token" // permission to register; only "serve" sends it
	HeaderConn   = "X-PF-Tunnel-Conn"
	HeaderName   = "X-PF-Tunnel-Name" // what the tunnel is called in the console; URL-escaped
	HeaderTarget = "X-PF-Tunnel-Target"
	HeaderError  = "X-PF-Tunnel-Error"

	MinSecret = 32
	MaxSecret = 128

	// The serving side pings its control channel; either end gives up on it
	// after ControlSilence.
	controlPing    = 20 * time.Second
	ControlSilence = 60 * time.Second
)

// A word names one tunnel and is typed on both sides, so it is short and
// easy to read out: three groups of four letters or digits, in any case.
// A generated word leaves out the characters that are mistaken for one
// another (0 and o, 1, i and l); it carries 59 bits, and can only be guessed
// against the live server, one request at a time. A typed word may use any
// letter or digit.
const (
	wordAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	wordExample  = "k3f9-x2mq-7hpa"
)

var wordPattern = regexp.MustCompile(`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)

// NormalizeWord checks a word and returns it in the lower case both ends
// use from then on.
func NormalizeWord(word string) (string, error) {
	word = strings.ToLower(strings.TrimSpace(word))
	if !wordPattern.MatchString(word) {
		return "", fmt.Errorf("the word must be three groups of four letters or digits, like %s (case does not matter); leave it out and 'pf-client serve' makes a random one", wordExample)
	}
	return word, nil
}

// NewWord returns a random word that is easy to read out.
func NewWord() (string, error) {
	out := make([]byte, 0, 14)
	var b [1]byte
	for len(out) < 14 {
		if len(out) == 4 || len(out) == 9 {
			out = append(out, '-')
			continue
		}
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		if n := len(wordAlphabet); int(b[0]) < 256/n*n { // no modulo bias
			out = append(out, wordAlphabet[int(b[0])%n])
		}
	}
	return string(out), nil
}

// CheckSecret applies the rules for serve tokens: long enough to be a
// secret, and plain enough to travel in a header. what names the secret in
// the error.
func CheckSecret(what, secret string) error {
	if len(secret) < MinSecret {
		return fmt.Errorf("the %s must be at least %d characters long (got %d)", what, MinSecret, len(secret))
	}
	if len(secret) > MaxSecret {
		return fmt.Errorf("the %s must be at most %d characters long", what, MaxSecret)
	}
	for _, c := range secret {
		if c <= ' ' || c > '~' {
			return fmt.Errorf("the %s may only use printable ASCII characters, without spaces", what)
		}
	}
	return nil
}

// ControlMessage is what the relay sends down a serving side's control
// channel: open a connection to your target and bring it to /accept.
type ControlMessage struct {
	Open string `json:"open"`
}

// Client is the pf-client side of a relay.
type Client struct {
	base string // https://host[:port]
	word string
	tls  *tls.Config
	http *http.Client
	Logf func(format string, args ...any)
	// ServeToken is a serve token of the server, and Name what the tunnel is
	// called in the server's console. Only Serve needs them.
	ServeToken string
	Name       string
}

// NewClient checks the relay URL and the word. tlsConfig may be nil.
func NewClient(base, word string, tlsConfig *tls.Config) (*Client, error) {
	base, err := normalizeBase(base)
	if err != nil {
		return nil, err
	}
	word, err = NormalizeWord(word)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &Client{
		base: base, word: word, tls: tlsConfig,
		http: &http.Client{Timeout: handshakeLimit, Transport: transport},
		Logf: log.Printf,
	}, nil
}

// normalizeBase accepts the relay's address with or without the console's
// /pf path, and insists on https.
func normalizeBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q: use https://host[:port]/", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("invalid server URL %q: only https:// is supported", raw)
	}
	if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "/pf" {
		return "", fmt.Errorf("invalid server URL %q: give the server's address only, like https://%s/", raw, u.Host)
	}
	return "https://" + u.Host, nil
}

func (c *Client) header(conn string) http.Header {
	h := http.Header{}
	h.Set(HeaderWord, c.word)
	if conn != "" {
		h.Set(HeaderConn, conn)
	}
	return h
}

func (c *Client) dial(ctx context.Context, endpoint string, h http.Header) (*Conn, error) {
	return Dial(ctx, c.base+Path+"/"+endpoint, h, c.tls)
}

// get makes a plain request; anything but 2xx is a *StatusError.
func (c *Client) get(ctx context.Context, endpoint string, h http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+Path+"/"+endpoint, nil)
	if err != nil {
		return err
	}
	req.Header = h
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &StatusError{Code: resp.StatusCode, Msg: errorText(resp.Body)}
	}
	return nil
}

// explain turns the relay's refusals into something to act on.
func explain(err error) error {
	var se *StatusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.Code {
	case http.StatusForbidden:
		return errors.New("access denied")
	case http.StatusConflict:
		if se.Msg != "" {
			return errors.New(se.Msg)
		}
	case http.StatusNotFound:
		if se.Msg == "" {
			return errors.New("this server does not accept tunnels (it needs --tunnel or a [tunnel] table)")
		}
	}
	return err
}

// Check asks the relay whether someone is serving this word.
func (c *Client) Check(ctx context.Context) error {
	return explain(c.get(ctx, "check", c.header("")))
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Retry timing; variables so tests can shorten them.
var (
	// A failed attempt is retried after retryMin, doubling up to retryMax.
	retryMin = time.Second
	retryMax = 30 * time.Second
	// settled is how long a control channel must have lasted for the next
	// failure to start again from retryMin. A link that comes up and drops
	// straight away keeps backing off instead of retrying every second.
	settled = time.Minute
	// A tunnel that is up is checked again this often by Watch.
	recheck = 30 * time.Second
)

// Serve offers target to whoever connects with the same word, for ever: it
// returns only when ctx ends, or when the relay refuses the very first
// registration for a reason that waiting cannot cure (a wrong serve token,
// a word that belongs to someone else), which is a mistake to report rather
// than retry. Everything else, including a relay that is down from the
// start, is retried with a growing pause. The connections that were open
// end with a lost relay, and the connecting side opens new ones.
func (c *Client) Serve(ctx context.Context, target string) error {
	h := c.header("")
	h.Set(HeaderTarget, target)
	h.Set(HeaderServe, c.ServeToken)
	h.Set(HeaderName, url.QueryEscape(c.Name))
	backoff, served := retryMin, false
	for attempt := 1; ; attempt++ {
		ws, err := c.dial(ctx, "serve", h)
		if ctx.Err() != nil {
			if ws != nil {
				_ = ws.Close()
			}
			return nil
		}
		if err != nil {
			var se *StatusError
			if !served && errors.As(err, &se) && se.Final() {
				return explain(err)
			}
			c.Logf("cannot register with %s (%v); attempt %d, trying again in %s", c.base, explain(err), attempt, backoff)
		} else {
			if served {
				c.Logf("registered again with %s after %d attempt(s): serving %q, tunnel %s -> %s", c.base, attempt, c.Name, c.wordLabel(), target)
			} else {
				c.Logf("registered with %s: serving %q, tunnel %s -> %s", c.base, c.Name, c.wordLabel(), target)
			}
			served, attempt = true, 0
			started := time.Now()
			err = c.control(ctx, ws, target)
			if ctx.Err() != nil {
				return nil
			}
			if time.Since(started) >= settled {
				backoff = retryMin
			}
			c.Logf("lost the server after %s (%v); its connections are closed; registering again in %s", fmtAge(time.Since(started)), err, backoff)
		}
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, retryMax)
	}
}

// Watch reports, in the log, whether the tunnel can be reached, until ctx
// ends. It is for the connecting side, which keeps listening either way:
// a tunnel that is not there yet, or goes away, costs nothing but refused
// connections until it is back.
func (c *Client) Watch(ctx context.Context) {
	backoff, up := retryMin, false
	for first := true; ; first = false {
		err := c.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := recheck
		switch {
		case err == nil:
			if !up {
				c.Logf("the tunnel is up")
			}
			up, backoff = true, retryMin
		default:
			if up || first {
				c.Logf("the tunnel is not available (%v): the word is wrong or nobody is serving it yet; connections are refused until it is, and this keeps checking", err)
			}
			up, wait = false, backoff
			backoff = min(backoff*2, retryMax)
		}
		if !sleep(ctx, wait) {
			return
		}
	}
}

// control runs one control channel until it fails.
func (c *Client) control(ctx context.Context, ws *Conn, target string) error {
	defer ws.Close()
	ws.SetTimeouts(ControlSilence, WriteTimeout)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(controlPing)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = ws.WriteFrame(OpClose, nil)
				_ = ws.Close()
				return
			case <-stop:
				return
			case <-t.C:
				if ws.WriteFrame(OpPing, nil) != nil {
					_ = ws.Close()
					return
				}
			}
		}
	}()
	for {
		op, payload, err := ws.Next(MaxSmallFrame)
		if err != nil {
			return err
		}
		var msg ControlMessage
		if op == OpText && json.Unmarshal(payload, &msg) == nil && msg.Open != "" {
			go c.serveConn(ctx, msg.Open, target)
		}
	}
}

// serveConn carries one connection the relay asked for.
func (c *Client) serveConn(ctx context.Context, id, target string) {
	h := c.header(id)
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		c.Logf("connection %s failed: cannot reach the target %s: %v", short(id), target, err)
		h.Set(HeaderError, "the serving side could not reach its target")
		if err := c.get(ctx, "accept", h); err != nil {
			c.Logf("connection %s: could not tell the server: %v", short(id), explain(err))
		}
		return
	}
	ws, err := c.dial(ctx, "accept", h)
	if err != nil {
		c.Logf("connection %s failed: cannot bring it to the server: %v", short(id), explain(err))
		_ = conn.Close()
		return
	}
	c.Logf("connection %s open: tunnel -> %s", short(id), target)
	stream := NewStream(ws)
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	c.logEnd(short(id), time.Now(), bridge(ctx, stream, conn.(*net.TCPConn), partyServe), true)
}

func short(id string) string { return id[:min(len(id), 8)] }

// wordLabel is the word as logs show it: enough to tell tunnels apart, not
// enough to connect.
func (c *Client) wordLabel() string { return c.word[:4] + "-…" }

func fmtBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func fmtAge(d time.Duration) string {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// logEnd reports a finished connection: how long it lasted, what it carried
// each way, and why it ended. The directions are named from the two ends of
// the whole tunnel, so both clients' logs read the same.
func (c *Client) logEnd(id string, started time.Time, e ended, serving bool) {
	toTarget, toApp := e.toFar, e.toLocal
	if serving { // here "local" is the target
		toTarget, toApp = e.toLocal, e.toFar
	}
	c.Logf("connection %s closed after %s: app->target %s, target->app %s; %s",
		id, fmtAge(time.Since(started)), fmtBytes(toTarget), fmtBytes(toApp), e.reason)
}

// localConn is the application's end: a TCP connection, or stdin/stdout.
type localConn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// copyEnd is how one direction of a connection stopped. Both nil: the
// source finished cleanly.
type copyEnd struct{ readErr, writeErr error }

func (e copyEnd) clean() bool { return e.readErr == nil && e.writeErr == nil }

// copyChunks is io.Copy with a buffer the size of the largest frame, a
// running byte count, and a result that says which side failed. Each read
// becomes one WebSocket frame, so a busy stream, whose reads come back
// full, travels in few large frames; nothing waits to be merged.
func copyChunks(dst io.Writer, src io.Reader, count *atomic.Int64) copyEnd {
	buf := make([]byte, chunkSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return copyEnd{writeErr: werr}
			}
			count.Add(int64(n))
		}
		if err == io.EOF {
			return copyEnd{}
		}
		if err != nil {
			return copyEnd{readErr: err}
		}
	}
}

// ended is the outcome of one carried connection.
type ended struct {
	toFar, toLocal int64  // bytes sent into the tunnel, and delivered from it
	reason         string // why it ended, for the log
	err            error  // nil after a clean finish
}

// party names the ends of the chain as one pf-client sees them, so a reason
// can say which hop broke:
//
//	application -- pf-client connect == server == pf-client serve -- target
type party struct {
	self  string // this program
	local string // what its TCP connection goes to
	far   string // what is at the other end of the tunnel
}

var (
	partyConnect = party{self: "pf-client connect", local: "the application", far: "the target"}
	partyServe   = party{self: "pf-client serve", local: "the target", far: "the application"}
)

// linkReason words a failure of the stream to the server. A *RemoteError is
// the cause as the server or the other pf-client reported it, and is
// already specific.
func (p party) linkReason(err error) string {
	var remote *RemoteError
	var netErr net.Error
	switch {
	case errors.As(err, &remote):
		return remote.Reason
	case errors.Is(err, ErrPeerClosed):
		return "the server closed the connection"
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("the link between %s and the server was silent for %s", p.self, linkSilence)
	}
	return fmt.Sprintf("the link between %s and the server was lost (%v)", p.self, err)
}

// localReason words a failure of the local TCP connection.
func (p party) localReason(err error) string {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return p.local + " reset its connection to " + p.self
	}
	return fmt.Sprintf("the connection between %s and %s failed (%v)", p.self, p.local, err)
}

// bridge copies both ways until both directions finish cleanly or either
// fails, then closes both ends. When this end is the one that saw the
// break, it tells the far end why, so both logs name the same cause.
func bridge(ctx context.Context, sess *Stream, local localConn, p party) ended {
	// If this program is stopped, whoever closes the stream says so.
	sess.CloseReason = func() string {
		if ctx.Err() != nil {
			return p.self + " is stopping"
		}
		return ""
	}
	var toFar, toLocal atomic.Int64
	type result struct {
		outbound bool // local -> tunnel
		end      copyEnd
	}
	results := make(chan result, 2)
	go func() {
		end := copyChunks(sess, local, &toFar)
		if end.clean() {
			end.writeErr = sess.CloseWrite()
		}
		results <- result{true, end}
	}()
	go func() {
		end := copyChunks(local, sess, &toLocal)
		if end.clean() {
			_ = local.CloseWrite()
		}
		results <- result{false, end}
	}()
	// describe words one direction's end. mine is true when the cause is on
	// this side of the tunnel, which the far end cannot see for itself.
	describe := func(r result) (reason string, mine bool, err error) {
		switch {
		case r.end.clean() && r.outbound:
			return p.local + " closed the connection", true, nil
		case r.end.clean():
			return p.far + " closed the connection", false, nil
		case r.outbound && r.end.readErr != nil:
			return p.localReason(r.end.readErr), true, r.end.readErr
		case r.outbound:
			return p.linkReason(r.end.writeErr), false, r.end.writeErr
		case r.end.readErr != nil:
			// A silent link may still carry what this end sends, so say so.
			var netErr net.Error
			silent := errors.As(r.end.readErr, &netErr) && netErr.Timeout()
			return p.linkReason(r.end.readErr), silent, r.end.readErr
		}
		return p.localReason(r.end.writeErr), true, r.end.writeErr
	}

	reason, mine, err := describe(<-results)
	if err == nil {
		// One direction finished cleanly. Unless more is learned, the
		// reason stays who closed first. If that was the far end's
		// half-close, nothing reads the stream any more, so watch for the
		// far end going away while this end still has the floor.
		then := func(r result) {
			if why, whose, failed := describe(r); failed != nil {
				reason, mine, err = why, whose, failed
			}
		}
		select {
		case second := <-results:
			then(second)
		case <-sess.Gone():
			// After a clean finish the far end's close and our own last
			// result arrive together; give ours a moment before deciding
			// the far end left while we were still sending.
			select {
			case second := <-results:
				then(second)
			case <-time.After(200 * time.Millisecond):
				mine, err = false, ErrPeerClosed
				if reason = sess.GoneReason(); reason == "" {
					reason = "the server closed the connection"
				}
			}
		}
	}
	if ctx.Err() != nil {
		reason, mine, err = p.self+" is stopping", true, ctx.Err()
	}
	if mine && err != nil {
		sess.Fail(reason)
	} else {
		_ = sess.Close()
	}
	_ = local.Close()
	return ended{toFar: toFar.Load(), toLocal: toLocal.Load(), reason: reason, err: err}
}

// Connect forwards every connection accepted on ln to the serving side.
func (c *Client) Connect(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			_ = c.carry(ctx, conn.(*net.TCPConn), conn.RemoteAddr().String())
		}()
	}
}

// ConnectOne carries a single connection, and logs how it went.
func (c *Client) ConnectOne(ctx context.Context, local localConn) error {
	return c.carry(ctx, local, "stdin/stdout")
}

func (c *Client) carry(ctx context.Context, local localConn, from string) error {
	ws, err := c.dial(ctx, "connect", c.header(""))
	if err != nil {
		_ = local.Close()
		err = explain(err)
		c.Logf("connection from %s refused: %v", from, err)
		return err
	}
	id, started := short(ws.Header.Get(HeaderConn)), time.Now()
	c.Logf("connection %s open: %s -> tunnel %s", id, from, c.wordLabel())
	stream := NewStream(ws)
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	e := bridge(ctx, stream, local, partyConnect)
	c.logEnd(id, started, e, false)
	return e.err
}

// Stdio is standard input and output as one connection, for use as an ssh
// ProxyCommand.
type Stdio struct {
	In  io.ReadCloser
	Out io.WriteCloser
}

func (s Stdio) Read(p []byte) (int, error)  { return s.In.Read(p) }
func (s Stdio) Write(p []byte) (int, error) { return s.Out.Write(p) }
func (s Stdio) CloseWrite() error           { return s.Out.Close() }
func (s Stdio) Close() error                { return s.In.Close() }

// ---------- certificate trust ----------

// ProbeCert connects once and returns the server's certificate, together
// with the reason it does not verify (nil when it does).
func ProbeCert(ctx context.Context, base string) (leaf *x509.Certificate, verifyErr error, err error) {
	base, err = normalizeBase(base)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(base)
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, errors.New("the server sent no certificate")
	}
	opts := x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: x509.NewCertPool()}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, verifyErr = certs[0].Verify(opts)
	return certs[0], verifyErr, nil
}

// Fingerprint is the certificate's SHA-256, as AA:BB:...
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	text := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(text); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(text[i : i+2])
	}
	return b.String()
}

// PinnedTLS accepts exactly this certificate and nothing else.
func PinnedTLS(cert *x509.Certificate) *tls.Config {
	want := sha256.Sum256(cert.Raw)
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by the check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].Raw) != want {
				return errors.New("the server's certificate is not the one that was trusted")
			}
			return nil
		},
	}
}
