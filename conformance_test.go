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
	"os"
	"os/exec"
	"path/filepath"
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

type driver []string

func conformanceDriver(t *testing.T) driver {
	t.Helper()
	if d := os.Getenv("PF_CONFORMANCE_DRIVER"); d != "" {
		return strings.Fields(d)
	}
	bin := filepath.Join(t.TempDir(), "go-driver")
	out, err := exec.Command("go", "build", "-o", bin, "./conformance/go-driver").CombinedOutput()
	if err != nil {
		t.Fatalf("building the Go driver: %v\n%s", err, out)
	}
	return driver{bin}
}

// proc is one run of the driver.
type proc struct {
	t      *testing.T
	cmd    *exec.Cmd
	lines  chan string
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
	ca string
	d  driver
}

func newConformanceHub(t *testing.T, d driver) *conformanceHub {
	caPEM, leaf, pool := conformanceCerts(t)
	f := newRelayFixtureTLS(t, "", leaf, pool)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &conformanceHub{relayFixture: f, ca: ca, d: d}
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
func (h *conformanceHub) run(t *testing.T, cmd string, args ...string) *proc {
	t.Helper()
	argv := append(append([]string{}, h.d[1:]...), cmd, "--server", h.srv.URL, "--ca", h.ca)
	argv = append(argv, args...)
	c := exec.Command(h.d[0], argv...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &proc{t: t, cmd: c, lines: make(chan string, 100), stderr: &syncBuffer{}, exited: make(chan struct{})}
	c.Stderr = p.stderr
	if err := c.Start(); err != nil {
		t.Fatalf("starting the driver: %v", err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
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
		select {
		case l, ok := <-p.lines:
			if !ok {
				<-p.exited
				p.t.Fatalf("the driver exited (%d) without saying %q; stderr:\n%s", p.code, prefix, p.stderr)
			}
			if strings.HasPrefix(l, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(l, prefix))
			}
		case <-deadline:
			p.t.Fatalf("the driver did not say %q within %s; stderr:\n%s", prefix, within, p.stderr)
		}
	}
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
	p := h.run(t, "serve", append([]string{"--word", testWord, "--target", target}, args...)...)
	p.line("ready", 15*time.Second)
	return p
}

// connect starts the driver connecting to testWord and returns the address
// it listens on.
func (h *conformanceHub) connect(t *testing.T, args ...string) string {
	t.Helper()
	p := h.run(t, "connect", append([]string{"--word", testWord, "--listen", "127.0.0.1:0"}, args...)...)
	return p.line("listening ", 15*time.Second)
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

func TestConformance(t *testing.T) {
	d := conformanceDriver(t)
	const exitProto, exitDenied = 3, 4
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	payload := randomBytes(1 << 20)

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
		if code := h.run(t, "check", "--word", testWord).exit(15 * time.Second); code != exitDenied {
			t.Errorf("check with nobody serving exits %d, want %d", code, exitDenied)
		}
		h.goServe(t, ctx, echoTarget(t))
		if code := h.run(t, "check", "--word", testWord).exit(15 * time.Second); code != 0 {
			t.Errorf("check of a served word exits %d", code)
		}
	})

	t.Run("client token", func(t *testing.T) {
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
		if code := h.run(t, "check", "--word", testWord).exit(15 * time.Second); code != exitDenied {
			t.Errorf("check without the client token exits %d, want %d", code, exitDenied)
		}
		if code := h.run(t, "check", "--word", testWord, "--client-token", "open-sesame").exit(15 * time.Second); code != 0 {
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
		p := h.run(t, "serve", "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", "wrong-serve-token-0123456789abcdef")
		if code := p.exit(15 * time.Second); code != exitDenied {
			t.Errorf("exit %d, want %d; stderr:\n%s", code, exitDenied, p.stderr)
		}
	})

	t.Run("serve/a word of another tenant is final", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.goServe(t, ctx, echoTarget(t)) // alice binds the word
		p := h.run(t, "serve", "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", testServeToken2)
		if code := p.exit(15 * time.Second); code == 0 || code == exitProto {
			t.Errorf("exit %d; stderr:\n%s", code, p.stderr)
		}
		if !strings.Contains(p.stderr.String(), "another tenant") {
			t.Errorf("the hub's reason is not shown: %s", p.stderr)
		}
	})

	t.Run("serve/anonymous", func(t *testing.T) {
		h := newConformanceHub(t, d)
		p := h.run(t, "serve", "--word", testWord, "--target", "127.0.0.1:1")
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

	t.Run("protocol 0 hub", func(t *testing.T) {
		h := newConformanceHub(t, d)
		h.hub.mu.Lock()
		h.hub.silent = true
		h.hub.mu.Unlock()
		p := h.run(t, "serve", "--word", testWord, "--target", "127.0.0.1:1", "--serve-token", testServeToken, "--client-token", "open-sesame")
		if code := p.exit(15 * time.Second); code != exitProto {
			t.Errorf("serve with a client token exits %d, want %d; stderr:\n%s", code, exitProto, p.stderr)
		}
		if code := h.run(t, "check", "--word", testWord, "--client-token", "open-sesame").exit(15 * time.Second); code != exitProto {
			t.Errorf("check with a client token exits %d, want %d", code, exitProto)
		}
		// A plain tunnel works with it.
		h.serve(t, echoTarget(t), "--serve-token", testServeToken)
		if err := echoTCP(h.connect(t), payload[:1000]); err != nil {
			t.Error(err)
		}
	})

	t.Run("version", func(t *testing.T) {
		h := newConformanceHub(t, d)
		if code := h.run(t, "version", "--serve-token", "wrong-serve-token-0123456789abcdef").exit(15 * time.Second); code != exitDenied {
			t.Errorf("version with a wrong serve token exits %d, want %d", code, exitDenied)
		}
		p := h.run(t, "version", "--serve-token", testServeToken)
		var info tunnel.ServerInfo
		line := p.line("", 15*time.Second)
		if err := json.Unmarshal([]byte(line), &info); err != nil {
			t.Fatalf("version printed %q: %v", line, err)
		}
		if info.Version != version || info.ProtoMin != tunnel.ProtoMin || info.ProtoMax != tunnel.ProtoMax || info.Token != "alice" {
			t.Errorf("version printed %+v", info)
		}
		if code := p.exit(15 * time.Second); code != 0 {
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

	t.Run("idle connections stay up", func(t *testing.T) {
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
