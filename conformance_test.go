package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
	"github.com/wushilin/pf-simple/pfrelay"
)

// The conformance suite: a real hub, and an SDK's driver program put
// through every case of docs/PROTOCOL.md, against itself and against the Go
// SDK. See conformance/README.md.
//
//	PF_CONFORMANCE_DRIVER="python3 -I sdk/python/driver.py" go test -run TestConformance .
//
// Without PF_CONFORMANCE_DRIVER it runs the Go SDK's own driver.
// PF_CONFORMANCE_SLOW=1 adds the cases that take a minute.

// driver is an SDK's driver, and the configuration a run puts it in.
type driver struct {
	argv   []string
	speaks int // the newest protocol it speaks, from "protocols"; 1 without that command
	// protoMax is the newest protocol it is told to offer (--proto-max);
	// 0 announces none. hub is the hub's newest: 2, 1 (like 0.14) or 0
	// (like a hub from before 0.14).
	protoMax, hub int
}

// common is the protocol the two sides end up with.
func (d driver) common() int { return min(d.hub, d.protoMax) }

// reuse says whether legs are reused in this configuration.
func (d driver) reuse() bool { return d.common() >= 2 }

// The driver's commands, modes and queries (conformance/README.md).
type (
	driverCommand string
	driverMode    string
	driverQuery   string
)

const (
	cmdServe     driverCommand = "serve"
	cmdConnect   driverCommand = "connect"
	cmdCheck     driverCommand = "check"
	cmdVersion   driverCommand = "version"
	cmdProtocols driverCommand = "protocols"

	modeListen  driverMode = "listen"
	modeForward driverMode = "forward"

	queryStats driverQuery = "stats"
	queryConns driverQuery = "conns"
	queryDrop  driverQuery = "drop" // "drop <id>"

	// The lines the driver prints for the SDK's events.
	eventOpened  = "opened "  // "opened <id> <side>"
	eventClosed  = "closed "  // "closed <id> <sent> <received> ok|failed"
	eventRefused = "refused " // "refused <id>"

	// The driver's exit codes.
	exitOK     = 0
	exitProto  = 3
	exitDenied = 4
)

func conformanceDriver(t *testing.T) driver {
	t.Helper()
	var argv []string
	if d := os.Getenv("PF_CONFORMANCE_DRIVER"); d != "" {
		argv = strings.Fields(d)
	} else {
		bin := filepath.Join(t.TempDir(), "go-driver")
		out, err := exec.Command("go", "build", "-o", bin, "./conformance/go-driver").CombinedOutput()
		if err != nil {
			t.Fatalf("building the Go driver: %v\n%s", err, out)
		}
		argv = []string{bin}
	}
	d := driver{argv: argv, speaks: 1}
	// A driver from before the protocols command speaks 0-1.
	out, err := exec.Command(argv[0], append(append([]string{}, argv[1:]...), string(cmdProtocols))...).Output()
	if err == nil {
		if _, max, perr := tunnel.ParseProtoRange(strings.TrimSpace(string(out))); perr == nil {
			d.speaks = max
		}
	}
	d.protoMax, d.hub = d.speaks, tunnel.ProtoMax
	return d
}

// proc is one run of the driver.
type proc struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin io.WriteCloser
	// out is every line the driver printed. line reads it in order from
	// next; lines that do not match are passed over, but stay in out.
	mu     sync.Mutex
	out    []string
	next   int
	eof    bool
	more   chan struct{} // a line arrived, or the output ended
	stderr *syncBuffer
	exited chan struct{}
	code   int
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// conformanceHub is a hub for the suite, and the PEM file of its
// certificate for the driver.
type conformanceHub struct {
	*relayFixture
	ca     string
	d      driver
	server string          // the URL the driver is given; the hub's, or a proxy's
	leaf   tls.Certificate // the hub's certificate, for a proxy in front of it
	roots  *x509.CertPool  // what trusts it
}

func newConformanceHub(t *testing.T, d driver) *conformanceHub {
	caPEM, leaf, pool := conformanceCerts(t)
	f := newRelayFixtureTLS(t, "", leaf, pool)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	f.hub.mu.Lock()
	switch d.hub {
	case 0:
		f.hub.silent = true
	case 1:
		f.hub.maxProto = 1
	}
	f.hub.mu.Unlock()
	return &conformanceHub{relayFixture: f, ca: ca, d: d, server: f.srv.URL, leaf: leaf, roots: pool}
}

// conformanceCerts makes what a real deployment has: a CA, and a server
// certificate for 127.0.0.1 that it signed. httptest's own certificate is
// a self-signed CA used as the server's certificate, which strict TLS
// stacks such as rustls rightly refuse.
func conformanceCerts(t *testing.T) (caPEM []byte, leaf tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pf-simple conformance CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	leaf = tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf, pool
}

// run starts the driver with a command and flags; the hub's URL and
// certificate are added.
func (h *conformanceHub) run(t *testing.T, cmd driverCommand, args ...string) *proc {
	t.Helper()
	argv := append(append([]string{}, h.d.argv[1:]...), string(cmd), "--server", h.server, "--ca", h.ca)
	if h.d.protoMax < h.d.speaks {
		argv = append(argv, "--proto-max", strconv.Itoa(h.d.protoMax))
	}
	argv = append(argv, args...)
	c := exec.Command(h.d.argv[0], argv...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &proc{t: t, cmd: c, stdin: stdin, more: make(chan struct{}, 1), stderr: &syncBuffer{}, exited: make(chan struct{})}
	c.Stderr = p.stderr
	if err := c.Start(); err != nil {
		t.Fatalf("starting the driver: %v", err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			p.mu.Lock()
			p.out = append(p.out, sc.Text())
			p.mu.Unlock()
			p.wake()
		}
		p.mu.Lock()
		p.eof = true
		p.mu.Unlock()
		p.wake()
		err := c.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			p.code = ee.ExitCode()
		}
		close(p.exited)
	}()
	t.Cleanup(p.stop)
	return p
}

func (p *proc) stop() {
	select {
	case <-p.exited:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
}

// line waits for a line of output that starts with prefix.
func (p *proc) line(prefix string, within time.Duration) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		p.mu.Lock()
		for ; p.next < len(p.out); p.next++ {
			if l := p.out[p.next]; strings.HasPrefix(l, prefix) {
				p.next++
				p.mu.Unlock()
				return strings.TrimSpace(strings.TrimPrefix(l, prefix))
			}
		}
		eof := p.eof
		p.mu.Unlock()
		if eof {
			<-p.exited
			p.t.Fatalf("the driver exited (%d) without saying %q; stderr:\n%s", p.code, prefix, p.stderr)
		}
		select {
		case <-p.more:
		case <-deadline:
			p.t.Fatalf("the driver did not say %q within %s; stderr:\n%s", prefix, within, p.stderr)
		}
	}
}

func (p *proc) wake() {
	select {
	case p.more <- struct{}{}:
	default:
	}
}

// printed is every line printed so far that starts with prefix, without
// the prefix.
func (p *proc) printed(prefix string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, l := range p.out {
		if strings.HasPrefix(l, prefix) {
			out = append(out, strings.TrimPrefix(l, prefix))
		}
	}
	return out
}

// ask sends the driver a query on stdin ("stats" or "conns") and decodes
// the JSON of its answer into v.
func (p *proc) ask(query driverQuery, v any) {
	p.t.Helper()
	p.askArg(query, "", v)
}

// askArg is ask with an argument, such as the connection to drop.
func (p *proc) askArg(query driverQuery, arg string, v any) {
	p.t.Helper()
	line := string(query)
	if arg != "" {
		line += " " + arg
	}
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		p.t.Fatalf("asking the driver %q: %v", query, err)
	}
	answer := p.line(string(query)+" ", 10*time.Second)
	if err := json.Unmarshal([]byte(answer), v); err != nil {
		p.t.Fatalf("the driver answered %q with %q: %v", query, answer, err)
	}
}

// driverStats and driverConn are what a driver answers to "stats" and
// "conns".
type driverStats struct {
	Opened   uint64 `json:"opened"`
	Active   uint64 `json:"active"`
	Failed   uint64 `json:"failed"`
	Sent     int64  `json:"sent"`
	Received int64  `json:"received"`
}

type driverConn struct {
	ID       string       `json:"id"`
	Side     pfrelay.Side `json:"side"`
	Sent     int64        `json:"sent"`
	Received int64        `json:"received"`
}

// exit waits for the driver to end and returns its exit code.
func (p *proc) exit(within time.Duration) int {
	p.t.Helper()
	select {
	case <-p.exited:
		return p.code
	case <-time.After(within):
		p.t.Fatalf("the driver did not exit within %s; stderr:\n%s", within, p.stderr)
	}
	return -1
}

// serve starts the driver serving testWord to target and waits until it
// is registered.
func (h *conformanceHub) serve(t *testing.T, target string, args ...string) *proc {
	t.Helper()
	p := h.run(t, cmdServe, append([]string{"--word", testWord, "--target", target}, args...)...)
	p.line("ready", 15*time.Second)
	return p
}

// connect starts the driver connecting to testWord and returns the address
// it listens on.
func (h *conformanceHub) connect(t *testing.T, args ...string) string {
	t.Helper()
	addr, _ := h.connectProc(t, args...)
	return addr
}

// connectProc is connect, and the driver's process.
func (h *conformanceHub) connectProc(t *testing.T, args ...string) (string, *proc) {
	t.Helper()
	p := h.run(t, cmdConnect, append([]string{"--word", testWord, "--listen", "127.0.0.1:0"}, args...)...)
	return p.line("listening ", 15*time.Second), p
}

// connIDs is every connection id the hub has open.
func (h *conformanceHub) connIDs() map[string]bool {
	ids := map[string]bool{}
	h.hub.mu.Lock()
	defer h.hub.mu.Unlock()
	for _, tn := range h.hub.tunnels {
		tn.mu.Lock()
		for _, id := range tn.connIDs {
			ids[id] = true
		}
		tn.mu.Unlock()
	}
	return ids
}

// goServe serves testWord to target with the Go SDK.
func (h *conformanceHub) goServe(t *testing.T, ctx context.Context, target string) {
	t.Helper()
	go func() { _ = h.client(t, testWord, testServeToken).Serve(ctx, target) }()
	c := h.client(t, testWord, "")
	waitFor(t, "the Go side to serve", func() bool { return c.Check(ctx) == nil })
}

// bannerTarget speaks first: it sends a line, half-closes, and then echoes
// nothing, as an SSH or SMTP server greets before it is spoken to.
func bannerTarget(t *testing.T) string {
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
				defer c.Close()
				_, _ = c.Write([]byte("hello from the target\n"))
				_ = c.(*net.TCPConn).CloseWrite()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func closedPort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// echoOver sends payload over conn, half-closes, and checks it all comes
// back followed by a clean end.
func echoOver(conn interface {
	io.ReadWriter
	CloseWrite() error
}, payload []byte) error {
	errs := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.CloseWrite()
		}
		errs <- err
	}()
	got, err := io.ReadAll(conn)
	if werr := <-errs; werr != nil {
		return fmt.Errorf("write: %w", werr)
	}
	if err != nil {
		return fmt.Errorf("read after %d bytes: %w", len(got), err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echoed %d bytes, not the %d sent", len(got), len(payload))
	}
	return nil
}

// echoTCP dials addr and runs echoOver.
func echoTCP(addr string, payload []byte) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	return echoOver(c.(*net.TCPConn), payload)
}

// parallel runs n copies of f and reports the first error.
func parallel(n int, f func(i int) error) error {
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- f(i) }()
	}
	var first error
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// TestConformance runs every case with the SDK's driver and the hub at each
// combination of protocol versions: so that a new SDK works with old hubs,
// and an SDK that behaves like an old client works with a new hub.
func TestConformance(t *testing.T) {
	base := conformanceDriver(t)
	seen := map[[2]int]bool{}
	for _, cfg := range []struct{ hub, client int }{
		{2, 2}, {2, 1}, {2, 0}, {1, 2}, {0, 2},
	} {
		d := base
		d.hub, d.protoMax = cfg.hub, min(cfg.client, base.speaks)
		if base.speaks < 2 && d.protoMax < base.speaks {
			continue // a driver from before protocol 2 cannot be told to offer less
		}
		if seen[[2]int{d.hub, d.protoMax}] {
			continue
		}
		seen[[2]int{d.hub, d.protoMax}] = true
		t.Run(fmt.Sprintf("hub %d, client %d", d.hub, d.protoMax), func(t *testing.T) {
			conformanceCases(t, d, cfg == struct{ hub, client int }{2, 2})
		})
	}
}

// conformanceCases runs every case that applies to d's configuration. main
// is the newest configuration, where the slow cases run.
func conformanceCases(t *testing.T, d driver, main bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	payload := randomBytes(1 << 20)
	// only runs a case where the protocols of the run allow it.
	only := func(ok bool, name string, f func(t *testing.T)) {
		if ok {
			t.Run(name, f)
		}
	}

	t.Run("serve/echo to a Go connector", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		c := h.client(t, testWord, "")
		if err := parallel(8, func(int) error {
			conn, err := c.Dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			return echoOver(conn, payload)
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("connect/echo through a Go server", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.goServe(t, ctx, echoTarget(t))
		addr := h.connect(t)
		if err := parallel(8, func(int) error { return echoTCP(addr, payload) }); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("both sides/echo", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		addr := h.connect(t)
		if err := parallel(4, func(int) error { return echoTCP(addr, payload) }); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("serve/the target speaks first", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, bannerTarget(t), "--serve-token", testServeToken)
		conn, err := h.client(t, testWord, "").Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		got, err := io.ReadAll(conn) // without sending anything
		if err != nil || string(got) != "hello from the target\n" {
			t.Fatalf("read %q, %v", got, err)
		}
	})

	t.Run("connect/the target speaks first", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.goServe(t, ctx, bannerTarget(t))
		c, err := net.Dial("tcp", h.connect(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		got, err := io.ReadAll(c)
		if err != nil || string(got) != "hello from the target\n" {
			t.Fatalf("read %q, %v", got, err)
		}
	})

	t.Run("serve/the target cannot be reached", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.hub.idle = 500 * time.Millisecond
		h.serve(t, closedPort(t), "--serve-token", testServeToken)
		conn, err := h.client(t, testWord, "").Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		if err == io.EOF { // passed on as a half-close; the reason follows
			waitFor(t, "the reason", func() bool { return conn.Err() != nil })
			err = conn.Err()
		}
		var remote *pfrelay.RemoteError
		if !errors.As(err, &remote) || remote.Reason == "" {
			t.Fatalf("the connecting side heard %v, not the serving side's reason", err)
		}
	})

	t.Run("connect/nobody serves the word", func(t *testing.T) {
		h := newConformanceHub(t, d)
		c, err := net.Dial("tcp", h.connect(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("read %d bytes, %v: the connection should end at once", n, err)
		}
	})

	t.Run("check", func(t *testing.T) {
		h := newConformanceHub(t, d)
		if code := h.run(t, cmdCheck, "--word", testWord).exit(15 * time.Second); code != exitDenied {
			t.Errorf("check with nobody serving exits %d, want %d", code, exitDenied)
		}
		h.goServe(t, ctx, echoTarget(t))
		if code := h.run(t, cmdCheck, "--word", testWord).exit(15 * time.Second); code != exitOK {
			t.Errorf("check of a served word exits %d", code)
		}
	})

	only(d.common() >= 1, "client token", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--client-token", "open-sesame")
		without := h.client(t, testWord, "")
		if _, err := without.Dial(ctx); !errors.Is(err, pfrelay.ErrAccessDenied) {
			t.Errorf("connecting without the client token = %v", err)
		}
		with := h.client(t, testWord, "")
		with.ClientToken = "open-sesame"
		conn, err := with.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoOver(conn, payload[:1000]); err != nil {
			t.Error(err)
		}
		conn.Close()
		if code := h.run(t, cmdCheck, "--word", testWord).exit(15 * time.Second); code != exitDenied {
			t.Errorf("check without the client token exits %d, want %d", code, exitDenied)
		}
		if code := h.run(t, cmdCheck, "--word", testWord, "--client-token", "open-sesame").exit(15 * time.Second); code != exitOK {
			t.Errorf("check with the client token exits %d", code)
		}
		// The driver's connect side sends it too.
		addr := h.connect(t, "--client-token", "open-sesame")
		if err := echoTCP(addr, payload[:1000]); err != nil {
			t.Error(err)
		}
	})

	t.Run("serve/a wrong serve token is final", func(t *testing.T) {
		h := newConformanceHub(t, d)
		p := h.run(t, cmdServe, "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", "wrong-serve-token-0123456789abcdef")
		if code := p.exit(15 * time.Second); code != exitDenied {
			t.Errorf("exit %d, want %d; stderr:\n%s", code, exitDenied, p.stderr)
		}
	})

	t.Run("serve/a word of another tenant is final", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.goServe(t, ctx, echoTarget(t)) // alice binds the word
		p := h.run(t, cmdServe, "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", testServeToken2)
		if code := p.exit(15 * time.Second); code == 0 || code == exitProto {
			t.Errorf("exit %d; stderr:\n%s", code, p.stderr)
		}
		if !strings.Contains(p.stderr.String(), "another tenant") {
			t.Errorf("the hub's reason is not shown: %s", p.stderr)
		}
	})

	only(d.common() >= 1, "serve/anonymous", func(t *testing.T) {
		h := newConformanceHub(t, d)
		p := h.run(t, cmdServe, "--word", testWord, "--target", "127.0.0.1:1")
		if code := p.exit(15 * time.Second); code != exitDenied {
			t.Errorf("anonymous serve where it is off exits %d, want %d", code, exitDenied)
		}
		h.hub.mu.Lock()
		h.hub.anonymous = true
		h.hub.mu.Unlock()
		h.serve(t, echoTarget(t))
		conn, err := h.client(t, testWord, "").Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := echoOver(conn, payload[:1000]); err != nil {
			t.Error(err)
		}
	})

	only(d.hub == 2 && d.protoMax >= 1, "protocol 0 hub", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.hub.mu.Lock()
		h.hub.silent = true
		h.hub.mu.Unlock()
		p := h.run(t, cmdServe, "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", testServeToken, "--client-token", "open-sesame")
		if code := p.exit(15 * time.Second); code != exitProto {
			t.Errorf("serve with a client token exits %d, want %d; stderr:\n%s", code, exitProto, p.stderr)
		}
		if code := h.run(t, cmdCheck, "--word", testWord, "--client-token", "open-sesame").exit(15 * time.Second); code != exitProto {
			t.Errorf("check with a client token exits %d, want %d", code, exitProto)
		}
		// A plain tunnel works with it.
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		if err := echoTCP(h.connect(t), payload[:1000]); err != nil {
			t.Error(err)
		}
	})

	only(d.hub >= 1, "version", func(t *testing.T) {
		h := newConformanceHub(t, d)
		if code := h.run(t, cmdVersion, "--serve-token", "wrong-serve-token-0123456789abcdef").exit(15 * time.Second); code != exitDenied {
			t.Errorf("version with a wrong serve token exits %d, want %d", code, exitDenied)
		}
		p := h.run(t, cmdVersion, "--serve-token", testServeToken)
		var info tunnel.ServerInfo
		line := p.line("", 15*time.Second)
		if err := json.Unmarshal([]byte(line), &info); err != nil {
			t.Fatalf("version printed %q: %v", line, err)
		}
		if info.Version != version || info.ProtoMin != tunnel.ProtoMin || info.ProtoMax != d.hub || info.Token != "alice" {
			t.Errorf("version printed %+v", info)
		}
		if code := p.exit(15 * time.Second); code != exitOK {
			t.Fatalf("version exits %d", code)
		}
	})

	t.Run("serve/registers again after losing the hub", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		h.hub.mu.Lock()
		var old *relayTunnel
		for _, tn := range h.hub.tunnels {
			old = tn
		}
		h.hub.mu.Unlock()
		h.hub.drop(old, "dropped by the conformance suite")
		waitFor(t, "the driver to register again", func() bool {
			h.hub.mu.Lock()
			defer h.hub.mu.Unlock()
			for _, tn := range h.hub.tunnels {
				return tn != old
			}
			return false
		})
		conn, err := h.client(t, testWord, "").Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := echoOver(conn, payload[:1000]); err != nil {
			t.Error(err)
		}
	})

	for _, mode := range []driverMode{modeListen, modeForward} {
		t.Run("stats/connect side ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			h.goServe(t, ctx, echoTarget(t))
			addr, p := h.connectProc(t, "--mode", string(mode))
			checkStats(t, h, p, pfrelay.SideConnect, func() (net.Conn, error) { return net.Dial("tcp", addr) })
		})
		t.Run("stats/serve side ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			p := h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--mode", string(mode))
			c := h.client(t, testWord, "")
			checkStats(t, h, p, pfrelay.SideServe, func() (net.Conn, error) { return c.Dial(ctx) })
		})
	}

	for _, mode := range []driverMode{modeListen, modeForward} {
		t.Run("serve/drop a connection by its id ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			h.hub.idle = 500 * time.Millisecond // the reason follows the half-close (PROTOCOL.md §8.3)
			p := h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--mode", string(mode))
			conn, err := h.client(t, testWord, "").Dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil { // the connection is up
				t.Fatal(err)
			}
			var dropped bool
			if p.askArg(queryDrop, "0000000000000000", &dropped); dropped {
				t.Error("dropped a connection that does not exist")
			}
			if p.askArg(queryDrop, conn.ID().String(), &dropped); !dropped {
				t.Fatalf("could not drop %s", conn.ID())
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, err = io.ReadAll(conn)
			var remote *pfrelay.RemoteError
			if !errors.As(err, &remote) && !errors.As(conn.Err(), &remote) {
				waitFor(t, "the reason", func() bool { return errors.As(conn.Err(), &remote) })
			}
			if !strings.Contains(remote.Reason, "dropped by the conformance suite") {
				t.Errorf("the connecting side heard %q", remote.Reason)
			}
			// The closed event may come before or after the answer to drop.
			var closed []string
			waitFor(t, "the closed event", func() bool {
				closed = p.printed(eventClosed + conn.ID().String())
				return len(closed) > 0
			})
			if len(closed) != 1 || !strings.HasSuffix(closed[0], " failed") {
				t.Errorf("closed events %q: a dropped connection is closed once, as failed", closed)
			}
		})
	}

	t.Run("forward/serve: echo to a Go connector", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--mode", string(modeForward))
		c := h.client(t, testWord, "")
		if err := parallel(8, func(int) error {
			conn, err := c.Dial(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			return echoOver(conn, payload)
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("forward/connect: echo through a Go server", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.goServe(t, ctx, echoTarget(t))
		addr := h.connect(t, "--mode", string(modeForward))
		if err := parallel(8, func(int) error { return echoTCP(addr, payload) }); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("forward/serve: an unreachable target is reported at once", func(t *testing.T) {
		// The forwarder dials the target before it answers, and refuses
		// through accept with a reason, so the hub's idle timeout plays
		// no part (PROTOCOL.md §9).
		h := newConformanceHub(t, d)
		h.serve(t, closedPort(t), "--serve-token", testServeToken, "--mode", string(modeForward))
		conn, err := h.client(t, testWord, "").Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		var remote *pfrelay.RemoteError
		if !errors.As(err, &remote) || remote.Reason == "" {
			t.Fatalf("the first read gave %v, not the serving side's reason", err)
		}
	})

	t.Run("connect/watch reports the tunnel coming up", func(t *testing.T) {
		h := newConformanceHub(t, d)
		_, p := h.connectProc(t)
		p.line("tunnel down", 15*time.Second)
		h.goServe(t, ctx, echoTarget(t))
		p.line("tunnel up", 15*time.Second) // checked again within 1s, 2s, 4s ...
	})

	t.Run("serve/retries with a growing pause", func(t *testing.T) {
		h := newConformanceHub(t, d)
		attempts := h.refuseServes(t, 3)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		times := attempts()
		if len(times) < 4 {
			t.Fatalf("%d attempts", len(times))
		}
		// 1s, then 2s, then 4s (PROTOCOL.md §9), with room for slow machines.
		for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
			if gap := times[i+1].Sub(times[i]); gap < want*7/10 || gap > want*15/10+300*time.Millisecond {
				t.Errorf("pause %d was %s, want about %s", i+1, gap.Round(10*time.Millisecond), want)
			}
		}
	})

	t.Run("serve/a full backlog refuses with a reason", func(t *testing.T) {
		// A serving side that does not accept holds at most 128
		// connections, and refuses the rest at once (PROTOCOL.md §9).
		h := newConformanceHub(t, d)
		p := h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--no-accept")
		c := h.client(t, testWord, "")
		const n = 140
		conns := make([]*pfrelay.Conn, 0, n)
		defer func() {
			for _, conn := range conns {
				conn.Close()
			}
		}()
		for i := 0; i < n; i++ {
			conn, err := c.Dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, conn)
		}
		refused := 0
		results := make(chan error, n)
		for _, conn := range conns {
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
				_, err := conn.Read(make([]byte, 1))
				results <- err
			}()
		}
		for range conns {
			var remote *pfrelay.RemoteError
			if err := <-results; errors.As(err, &remote) && remote.Reason != "" {
				refused++
			}
		}
		if refused != n-128 {
			t.Errorf("%d of %d connections were refused, want %d", refused, n, n-128)
		}
		if got := len(p.printed(eventRefused)); got != n-128 {
			t.Errorf("%d refusals reported as events, want %d", got, n-128)
		}
	})

	// Reusing the serving side's legs (protocol 2, PROTOCOL.md §12).
	for _, mode := range []driverMode{modeListen, modeForward} {
		only(d.reuse(), "reuse/sequential connections reuse a leg ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			p := h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--mode", string(mode))
			c := h.client(t, testWord, "")
			for i := 0; i < 5; i++ {
				conn, err := c.Dial(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := echoOver(conn, payload[:10000]); err != nil {
					t.Fatalf("connection %d: %v", i+1, err)
				}
				conn.Close()
				waitFor(t, "the leg to become idle", func() bool { return len(h.wordSnap(t).Idle) == 1 })
			}
			if w := h.wordSnap(t); !w.Reuse || w.Reused != 4 {
				t.Errorf("reuse %v, %d connections reused; want true, 4", w.Reuse, w.Reused)
			}
			// Each reused connection is a connection of its own to the SDK.
			waitFor(t, "five closed events", func() bool { return len(p.printed(eventClosed)) == 5 })
			for _, l := range p.printed(eventClosed) {
				if !strings.HasSuffix(l, " ok") {
					t.Errorf("event %q", eventClosed+l)
				}
			}
		})
	}
	only(!d.reuse(), "reuse/never with an older side", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		c := h.client(t, testWord, "")
		for i := 0; i < 3; i++ {
			conn, err := c.Dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := echoOver(conn, payload[:1000]); err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
		if w := h.wordSnap(t); w.Reused != 0 || len(w.Idle) != 0 {
			t.Errorf("%d connections reused, %d idle legs, between protocol %d and %d", w.Reused, len(w.Idle), d.hub, d.protoMax)
		}
	})
	only(d.reuse(), "reuse/an unreachable target on a reused leg is reported at once", func(t *testing.T) {
		h := newConformanceHub(t, d)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(c, c); c.Close() }()
			}
		}()
		h.serve(t, ln.Addr().String(), "--serve-token", testServeToken, "--mode", string(modeForward))
		c := h.client(t, testWord, "")
		conn, err := c.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoOver(conn, payload[:1000]); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		waitFor(t, "the leg to become idle", func() bool { return len(h.wordSnap(t).Idle) == 1 })
		ln.Close() // the target goes away
		conn, err = c.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// The forwarder answers bound before it dials, and reports the
		// failure after; the hub passes the reason on at once.
		_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		var remote *pfrelay.RemoteError
		if !errors.As(err, &remote) || remote.Reason == "" {
			t.Fatalf("the first read gave %v, not the serving side's reason", err)
		}
	})
	only(d.reuse(), "reuse/a failed connection's leg is not reused", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		c := h.client(t, testWord, "")
		conn, err := c.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		conn.Fail("the application gave up")
		time.Sleep(300 * time.Millisecond)
		if w := h.wordSnap(t); len(w.Idle) != 0 {
			t.Errorf("%d idle legs after a failed connection", len(w.Idle))
		}
		conn, err = c.Dial(ctx) // and the tunnel still works
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := echoOver(conn, payload[:1000]); err != nil {
			t.Fatal(err)
		}
	})

	// Connection leaks: after many connections, failed ones included, the
	// driver holds no more sockets than it did before them (Linux only).
	for _, mode := range []driverMode{modeListen, modeForward} {
		t.Run("leaks/serve side ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			p := h.serve(t, echoTarget(t), "--serve-token", testServeToken, "--mode", string(mode))
			c := h.client(t, testWord, "")
			round := func(n int) {
				for i := 0; i < n; i++ {
					conn, err := c.Dial(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if i%5 == 4 { // fails half way: the serving side must let go of it too
						_, _ = conn.Write([]byte("hello"))
						_, _ = io.ReadFull(conn, make([]byte, 5))
						conn.Fail("the conformance suite gave up")
						continue
					}
					if err := echoOver(conn, payload[:2000]); err != nil {
						t.Fatalf("connection %d: %v", i, err)
					}
					conn.Close()
				}
			}
			checkNoLeak(t, p, func() { round(20) }, func() { round(150) })
		})
		t.Run("leaks/connect side ("+string(mode)+")", func(t *testing.T) {
			h := newConformanceHub(t, d)
			h.goServe(t, ctx, echoTarget(t))
			addr, p := h.connectProc(t, "--mode", string(mode))
			round := func(n int) {
				for i := 0; i < n; i++ {
					tc, err := net.Dial("tcp", addr)
					if err != nil {
						t.Fatal(err)
					}
					if i%5 == 4 { // the application resets its connection half way
						_, _ = tc.Write([]byte("hello"))
						_, _ = io.ReadFull(tc, make([]byte, 5))
						_ = tc.(*net.TCPConn).SetLinger(0)
						tc.Close()
						continue
					}
					_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
					if err := echoOver(tc.(*net.TCPConn), payload[:2000]); err != nil {
						t.Fatalf("connection %d: %v", i, err)
					}
					tc.Close()
				}
			}
			checkNoLeak(t, p, func() { round(20) }, func() { round(150) })
		})
	}
	t.Run("leaks/connect side, nobody serving", func(t *testing.T) {
		h := newConformanceHub(t, d)
		addr, p := h.connectProc(t)
		round := func(n int) {
			for i := 0; i < n; i++ {
				tc, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				_ = tc.SetReadDeadline(time.Now().Add(20 * time.Second))
				_, _ = tc.Read(make([]byte, 1)) // refused: the driver closes it
				tc.Close()
			}
		}
		checkNoLeak(t, p, func() { round(10) }, func() { round(80) })
	})

	only(main, "idle connections stay up", func(t *testing.T) {
		if os.Getenv("PF_CONFORMANCE_SLOW") == "" {
			t.Skip("takes a minute; set PF_CONFORMANCE_SLOW=1")
		}
		h := newConformanceHub(t, d)
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		c, err := net.Dial("tcp", h.connect(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// Longer than both the stream's and the control channel's silence
		// limits: only the driver's pings keep them alive.
		time.Sleep(65 * time.Second)
		if err := echoOver(c.(*net.TCPConn), payload[:1000]); err != nil {
			t.Fatalf("after a minute idle: %v", err)
		}
	})
}

// checkStats runs connections through the driver's side of a tunnel and
// checks what it reports in "stats" and "conns" against the hub.
func checkStats(t *testing.T, h *conformanceHub, p *proc, side pfrelay.Side, open func() (net.Conn, error)) {
	t.Helper()
	echo := func(n int) {
		conn, err := open()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := echoOver(conn.(interface {
			io.ReadWriter
			CloseWrite() error
		}), randomBytes(n)); err != nil {
			t.Fatal(err)
		}
	}
	echo(1000)
	echo(2000)
	echo(3000)
	var st driverStats
	waitFor(t, "three closed connections", func() bool {
		p.ask(queryStats, &st)
		return st.Active == 0 && st.Opened == 3
	})
	if st.Failed != 0 || st.Sent != 6000 || st.Received != 6000 {
		t.Fatalf("after three connections, stats = %+v", st)
	}

	// One held open.
	conn, err := open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	var list []driverConn
	waitFor(t, "the open connection's figures", func() bool {
		p.ask(queryConns, &list)
		return len(list) == 1 && list[0].Sent == 5 && list[0].Received == 5
	})
	if c := list[0]; c.Side != side || !h.connIDs()[c.ID] {
		t.Errorf("conns = %+v; the hub has %v", list, h.connIDs())
	}
	p.ask(queryStats, &st)
	if st.Opened != 4 || st.Active != 1 || st.Sent != 6005 || st.Received != 6005 {
		t.Errorf("with one open, stats = %+v", st)
	}
	// Finish it cleanly: half-close, read to the far end's half-close,
	// then close. A close without that is a cut (PROTOCOL.md §8.4), which
	// either side may then report as failed.
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if rest, err := io.ReadAll(conn); err != nil || len(rest) != 0 {
		t.Errorf("finishing the open connection: %d more bytes, %v", len(rest), err)
	}
	conn.Close()
	waitFor(t, "the last connection to close", func() bool {
		p.ask(queryStats, &st)
		return st.Active == 0
	})
	p.ask(queryConns, &list)
	if len(list) != 0 {
		t.Errorf("conns after all closed = %+v", list)
	}

	// Every connection was opened once and closed once, with its figures.
	opened := map[string]bool{}
	for _, l := range p.printed(eventOpened) {
		var id, s string
		if _, err := fmt.Sscan(l, &id, &s); err != nil || pfrelay.Side(s) != side || opened[id] {
			t.Errorf("event %q", eventOpened+l)
		}
		opened[id] = true
	}
	var closed []string
	for _, l := range p.printed(eventClosed) {
		var id, outcome string
		var sent, received int64
		if _, err := fmt.Sscan(l, &id, &sent, &received, &outcome); err != nil || !opened[id] || outcome != "ok" || sent != received {
			t.Errorf("event %q", eventClosed+l)
		}
		closed = append(closed, fmt.Sprint(sent))
	}
	sort.Strings(closed)
	if len(opened) != 4 || strings.Join(closed, " ") != "1000 2000 3000 5" {
		t.Errorf("events: %d opened, closed with %v; want 4, and 1000 2000 3000 5", len(opened), closed)
	}
}

// refuseServes puts a proxy in front of the hub that answers the first n
// registrations with 503, and points the driver at it. It returns the
// times of the registration attempts so far.
func (h *conformanceHub) refuseServes(t *testing.T, n int) func() []time.Time {
	t.Helper()
	backend, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.roots}}
	var mu sync.Mutex
	var times []time.Time
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/serve") {
			mu.Lock()
			times = append(times, time.Now())
			refuse := len(times) <= n
			mu.Unlock()
			if refuse {
				w.Header().Set(tunnel.HeaderProto, "1")
				writeError(w, http.StatusServiceUnavailable, "the conformance suite refuses this registration")
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	front.TLS = &tls.Config{Certificates: []tls.Certificate{h.leaf}}
	front.StartTLS()
	t.Cleanup(front.Close)
	h.server = front.URL
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), times...)
	}
}

// checkNoLeak runs warm, which may open what the driver keeps (pooled and
// idle connections), counts the driver's open file descriptors, runs load,
// and checks the count came back: what load opened was all closed again.
func checkNoLeak(t *testing.T, p *proc, warm, load func()) {
	t.Helper()
	fds := func() int {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.cmd.Process.Pid))
		if err != nil {
			t.Skipf("cannot count the driver's file descriptors: %v", err)
		}
		return len(entries)
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("counting file descriptors needs /proc")
	}
	settle := func() int {
		// Closing finishes in the background (close handshakes, verdicts):
		// wait for the count to stop falling.
		last, same := fds(), 0
		for i := 0; i < 50 && same < 5; i++ {
			time.Sleep(200 * time.Millisecond)
			if n := fds(); n == last {
				same++
			} else {
				last, same = n, 0
			}
		}
		return last
	}
	warm()
	before := settle()
	load()
	after := settle()
	// A little slack for what a runtime opens on its own; a leak of one
	// socket per connection shows as dozens.
	if after > before+8 {
		t.Errorf("the driver held %d file descriptors before and %d after: about %d leaked over the connections", before, after, after-before)
	}
}
