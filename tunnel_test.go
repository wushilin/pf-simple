package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

const (
	testServeToken  = "serve-token-0123456789abcdefghijkl"
	testServeToken2 = "other-token-0123456789abcdefghijkl"
	testWord        = "k3f9-x2mq-7hpa"
	otherWord       = "zz22-zz33-zz44"
)

func tenantFor(name, token string) tenantSpec {
	sum := sha256.Sum256([]byte(token))
	return tenantSpec{Name: name, TokenSHA256: hex.EncodeToString(sum[:])}
}

func testTenants() []tenantSpec {
	return []tenantSpec{tenantFor("alice", testServeToken), tenantFor("bob", testServeToken2)}
}

type relayFixture struct {
	hub *tunnelHub
	srv *httptest.Server
	tls *tls.Config
}

func newRelayFixture(t *testing.T, statePath string) *relayFixture {
	t.Helper()
	mgr := newManager(nil, nil, halfCloseIdleTimeout)
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, statePath)
	hub.denyDelay = 5 * time.Millisecond
	hub.guesses.limit = 1 << 30 // the tests poll from one address until the word is served
	cs.tunnels = hub
	srv := httptest.NewTLSServer(cs.handler())
	t.Cleanup(func() {
		hub.closeAll()
		srv.CloseClientConnections()
		srv.Close()
	})
	return &relayFixture{hub: hub, srv: srv, tls: srv.Client().Transport.(*http.Transport).TLSClientConfig}
}

func (f *relayFixture) client(t *testing.T, word, serveToken string) *tunnel.Client {
	t.Helper()
	c, err := tunnel.NewClient(f.srv.URL, word, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	c.ServeToken, c.Name = serveToken, "Test tunnel"
	if os.Getenv("PF_TEST_LOG") == "" {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// echoTarget echoes each connection until its client half-closes.
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
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// serveAndConnect starts both sides and returns the connecting side's local
// address.
func (f *relayFixture) serveAndConnect(t *testing.T, ctx context.Context, target string) string {
	t.Helper()
	serveDone := make(chan error, 1)
	go func() { serveDone <- f.client(t, testWord, testServeToken).Serve(ctx, target) }()
	connector := f.client(t, testWord, "")
	waitFor(t, "the word to be served", func() bool {
		select {
		case err := <-serveDone:
			t.Fatalf("serve ended: %v", err)
		default:
		}
		return connector.Check(ctx) == nil
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go connector.Connect(ctx, ln)
	return ln.Addr().String()
}

func TestRelayEndToEnd(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := f.serveAndConnect(t, ctx, echoTarget(t))

	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 5)
	if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "hello" {
		t.Fatalf("echo = %q, %v", greeting, err)
	}

	snap := f.hub.snapshot()
	if len(snap.Words) != 1 || !snap.Words[0].Live || snap.Words[0].Word != testWord {
		t.Fatalf("snapshot = %+v", snap)
	}
	w := snap.Words[0]
	if w.Name != "Test tunnel" || w.Owner != "alice" || w.Conns != 1 || len(w.Sessions) != 1 || len(w.Sessions[0].ConnID) != 16 {
		t.Fatalf("word = %+v", w)
	}

	// Every byte must arrive, in order, and the half-close must travel both
	// ways: the echo target only closes after it has seen ours.
	payload := make([]byte, 5<<20)
	_, _ = rand.Read(payload)
	go func() {
		_, _ = conn.Write(payload)
		_ = conn.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d; equal prefix: %v", len(got), len(payload), bytes.HasPrefix(payload, got))
	}
	waitFor(t, "the session to end", func() bool { return f.hub.snapshot().Words[0].Conns == 0 })
	if w := f.hub.snapshot().Words[0]; w.BytesUp != uint64(len(payload)+5) || w.BytesDown != uint64(len(payload)+5) {
		t.Fatalf("bytes up/down = %d/%d, want %d", w.BytesUp, w.BytesDown, len(payload)+5)
	}
}

// A connection over stdin/stdout (ssh ProxyCommand) carries every byte and
// ends cleanly when the input does.
func TestRelayStdio(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.serveAndConnect(t, ctx, echoTarget(t))

	payload := make([]byte, 1<<20)
	_, _ = rand.Read(payload)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- f.client(t, testWord, "").ConnectOne(ctx, tunnel.Stdio{In: inR, Out: outW}) }()
	go func() {
		_, _ = inW.Write(payload)
		_ = inW.Close() // end of input: a half-close, the echo still comes back
	}()
	got, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
	}
	if err := <-done; err != nil {
		t.Fatalf("ConnectOne = %v, want a clean end", err)
	}
}

// A serving side on stdin/stdout carries one connection, refuses a second
// while it lasts, and ends with it.
func TestRelayServeStdio(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sent := make([]byte, 1<<20) // what the serving side pipes in
	_, _ = rand.Read(sent)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- f.client(t, testWord, testServeToken).ServeOne(ctx, tunnel.Stdio{In: inR, Out: outW})
	}()
	connector := f.client(t, testWord, "")
	waitFor(t, "the word to be served", func() bool { return connector.Check(ctx) == nil })
	if w := f.hub.snapshot().Words[0]; w.Target != tunnel.StdioTarget {
		t.Fatalf("target = %q", w.Target)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = connector.Connect(ctx, ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 5)
	if _, err := io.ReadFull(outR, hello); err != nil || string(hello) != "hello" {
		t.Fatalf("served side read %q, %v", hello, err)
	}

	// A second connection gets nothing: the one stream is taken.
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("second connection read %d bytes, err %v; want it closed", n, err)
	}

	// The first is unharmed: the piped input arrives whole, then its end.
	go func() {
		_, _ = inW.Write(sent)
		_ = inW.Close()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sent) {
		t.Fatalf("received %d bytes, want %d", len(got), len(sent))
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	if _, err := io.ReadAll(outR); err != nil {
		t.Fatalf("served side's output ended with %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeOne = %v, want a clean end", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeOne did not return")
	}
	// It left with its connection: nobody serves the word any more.
	waitFor(t, "the word to stop being served", func() bool { return connector.Check(ctx) != nil })
}

// A stdio serving side whose connection breaks reports it and stops. The
// break is on the far leg, so it arrives when the hub's drain time is up.
func TestRelayServeStdioBroken(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 30s drain")
	}
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inR, inW := io.Pipe()
	defer inW.Close()
	outR, outW := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, outR) }() // after the first byte, below
	served := make(chan error, 1)
	go func() {
		served <- f.client(t, testWord, testServeToken).ServeOne(ctx, tunnel.Stdio{In: inR, Out: outW})
	}()
	connector := f.client(t, testWord, "")
	waitFor(t, "the word to be served", func() bool { return connector.Check(ctx) == nil })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = connector.Connect(ctx, ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// Break it only once it has reached the serving side: one that never
	// got that far leaves the serving side waiting, with its input unread.
	waitFor(t, "the byte to cross", func() bool { return f.hub.snapshot().Words[0].BytesUp+f.hub.snapshot().Words[0].BytesDown > 0 })
	time.Sleep(200 * time.Millisecond)
	_ = conn.(*net.TCPConn).SetLinger(0) // a reset, not a clean close
	_ = conn.Close()
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("ServeOne = nil after a reset connection, want the reason")
		}
		if want := "the application reset its connection to pf-client connect"; err.Error() != want {
			t.Fatalf("ServeOne = %q, want %q", err, want)
		}
	case <-time.After(halfCloseIdleTimeout + 10*time.Second):
		t.Fatal("ServeOne did not return")
	}
}

func TestRelayRefusals(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.serveAndConnect(t, ctx, echoTarget(t))

	if err := f.client(t, otherWord, "").Check(ctx); err == nil || err.Error() != "access denied" {
		t.Fatalf("check with an unserved word = %v, want access denied", err)
	}
	// A connection with the wrong word is refused, not left hanging.
	if err := f.client(t, otherWord, "").ConnectOne(ctx, tunnel.Stdio{In: io.NopCloser(strings.NewReader("")), Out: nopWriteCloser{}}); err == nil || err.Error() != "access denied" {
		t.Fatalf("connect with an unserved word = %v, want access denied", err)
	}
	if err := f.client(t, otherWord, "not-a-serve-token-0123456789abcdefgh").Serve(ctx, "127.0.0.1:1"); err == nil || err.Error() != "access denied" {
		t.Fatalf("serve with an unknown serve token = %v, want access denied", err)
	}
	// The word belongs to the token that registered it.
	err := f.client(t, testWord, testServeToken2).Serve(ctx, "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("serve of another token's word = %v", err)
	}
	nameless := f.client(t, otherWord, testServeToken)
	nameless.Name = ""
	if err := nameless.Serve(ctx, "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("serve without a name = %v", err)
	}
	if _, err := tunnel.NewClient(f.srv.URL, "asdf123", f.tls); err == nil {
		t.Fatal("a malformed word was accepted")
	}
	// Case does not matter: both ends lower it before use.
	if err := f.client(t, strings.ToUpper(testWord), "").Check(ctx); err != nil {
		t.Fatalf("check with the word in upper case = %v", err)
	}
	if _, err := tunnel.NewClient(strings.Replace(f.srv.URL, "https://", "http://", 1), testWord, f.tls); err == nil {
		t.Fatal("an http:// server was accepted")
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// A reset ends the tunnel's connections; the serving side registers again on
// its own, and clearing the binding lets another token take the word.
func TestRelayResetAndClear(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := f.serveAndConnect(t, ctx, echoTarget(t))

	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	id := f.hub.snapshot().Words[0].ID
	if err := f.hub.reset(id, false); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read %d bytes from a connection whose tunnel was reset", n)
	}
	waitFor(t, "the serving side to register again", func() bool {
		w := f.hub.snapshot().Words
		return len(w) == 1 && w[0].Live && w[0].ID == id
	})

	cancel() // the serving side leaves; the binding stays
	waitFor(t, "the tunnel to go offline", func() bool { return !f.hub.snapshot().Words[0].Live })
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := f.client(t, testWord, testServeToken2).Serve(ctx2, "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "belongs to another") {
		t.Fatalf("serve of a bound, offline word = %v", err)
	}
	if err := f.hub.reset(id, true); err != nil {
		t.Fatal(err)
	}
	if err := f.hub.reset(id, true); err == nil {
		t.Fatal("clearing twice succeeded")
	}
	go f.client(t, testWord, testServeToken2).Serve(ctx2, "127.0.0.1:1")
	waitFor(t, "the other token to own the word", func() bool {
		w := f.hub.snapshot().Words
		return len(w) == 1 && w[0].Live && w[0].Owner == "bob"
	})
}

// When the target is down, the connecting side is told at once.
func TestRelayTargetUnreachable(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0") // a port nobody listens on
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	local := f.serveAndConnect(t, ctx, dead)
	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err != io.EOF || n != 0 {
		t.Fatalf("read = %d, %v; want the connection closed at once", n, err)
	}
	if w := f.hub.snapshot().Words[0]; w.Failed != 1 {
		t.Fatalf("failed = %d, want 1", w.Failed)
	}
}

func TestRelayBindingsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.relay.json")
	f := newRelayFixture(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	f.serveAndConnect(t, ctx, echoTarget(t))
	cancel()
	waitFor(t, "the tunnel to go offline", func() bool { return !f.hub.snapshot().Words[0].Live })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600: the file holds secrets", info.Mode().Perm())
	}
	again := newTunnelHub(testTenants()[:1], halfCloseIdleTimeout, func() int { return 0 }, path)
	w := again.snapshot().Words
	if len(w) != 1 || w[0].Word != testWord || w[0].Name != "Test tunnel" || w[0].Live || w[0].Owner != "alice" || w[0].Orphan {
		t.Fatalf("reloaded = %+v", w)
	}
}

func TestTunnelSettings(t *testing.T) {
	if _, err := parseArgs([]string{"--tunnel", testServeToken}, io.Discard, ""); err == nil || !strings.Contains(err.Error(), "--console") {
		t.Fatalf("--tunnel without --console = %v", err)
	}
	if _, err := parseArgs([]string{"--console", "18222", "--tunnel", "short"}, io.Discard, ""); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("a short serve token = %v", err)
	}
	if _, err := parseArgs([]string{"--console", "18222", "--tunnel", testServeToken, "--tunnel", testServeToken}, io.Discard, ""); err == nil {
		t.Fatal("the same serve token twice was accepted")
	}
	s, err := parseArgs([]string{"--console", "18222", "--tunnel", testServeToken, "--tunnel", testServeToken2}, io.Discard, "")
	if err != nil || s.tunnel == nil || len(s.tunnel.tenants) != 2 || s.tunnel.tenants[1].Name != "cli-2" || len(s.forwards) != 0 {
		t.Fatalf("console + tunnel alone = %+v, %v", s, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "pf.toml")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[tunnel]\n\n[[forward]]\nlisten = \"18080\"\ntarget = \"10.0.0.6\"\n")
	if _, err := loadConfig(path, ""); err == nil || !strings.Contains(err.Error(), "needs a [console]") {
		t.Fatalf("[tunnel] without [console] = %v", err)
	}
	for _, bad := range []string{
		"name = \"a b\"\ntoken_sha256 = \"" + tenantFor("x", testServeToken).TokenSHA256 + "\"",
		"name = \"alice\"\ntoken_sha256 = \"" + testServeToken + "\"", // the token itself, not its hash
	} {
		write("[console]\nlisten = \"18222\"\n\n[[tunnel.tenant]]\n" + bad + "\n")
		if _, err := loadConfig(path, ""); err == nil {
			t.Fatalf("accepted a bad tenant: %s", bad)
		}
	}
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\nenabled = false\n")
	if cfg, err := loadConfig(path, ""); err != nil || cfg.tunnel == nil || cfg.tunnel.enabled || cfg.tunnel.anonymous {
		t.Fatalf("enabled = false: %+v, %v", cfg.tunnel, err)
	}
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\nanonymous_serve = true\n")
	if cfg, err := loadConfig(path, ""); err != nil || cfg.tunnel == nil || !cfg.tunnel.enabled || !cfg.tunnel.anonymous {
		t.Fatalf("anonymous_serve = true: %+v, %v", cfg.tunnel, err)
	}
	write("[console]\nlisten = \"18222\"\n\n[[tunnel.tenant]]\nname = \"Anonymous\"\ntoken_sha256 = \"" + tenantFor("x", testServeToken).TokenSHA256 + "\"\n")
	if _, err := loadConfig(path, ""); err == nil || !strings.Contains(err.Error(), "taken") {
		t.Fatalf("a tenant named anonymous = %v", err)
	}
	if got := relayStatePath(path); got != filepath.Join(dir, "pf.relay.json") {
		t.Fatalf("relayStatePath = %s", got)
	}
}

// The hub's two switches are changed in the console and kept in the config
// file, which gets a [tunnel] table if it had none.
func TestRelaySwitches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.toml")
	if err := os.WriteFile(path, []byte("[console]\nlisten = \"18222\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path, "")
	if err != nil || cfg.tunnel != nil {
		t.Fatalf("loadConfig = %+v, %v", cfg.tunnel, err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.tunnelRaw = cfg.configPath, cfg.consoleRaw, cfg.tunnelRaw
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(nil, halfCloseIdleTimeout, mgr.allocID, relayStatePath(path))
	hub.enabled = false // what main does for a file without [tunnel]
	hub.denyDelay, hub.persist, hub.persistSettings = 5*time.Millisecond, mgr.saveTenants, mgr.saveTunnelSettings
	hub.guesses.limit = 1 << 30
	cs.tunnels = hub
	srv := httptest.NewTLSServer(cs.handler())
	defer func() {
		hub.closeAll()
		srv.CloseClientConnections()
		srv.Close()
	}()
	f := &relayFixture{hub: hub, srv: srv, tls: srv.Client().Transport.(*http.Transport).TLSClientConfig}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	set := func(body string) relayState {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/pf/api/relay/settings", strings.NewReader(body))
		req.Header.Set(csrfHeader, "1")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var state relayState
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&state) != nil {
			t.Fatalf("POST settings %s = %d", body, resp.StatusCode)
		}
		return state
	}
	saved := func() *tunnelSettings {
		t.Helper()
		cfg, err := loadConfig(path, "")
		if err != nil {
			t.Fatal(err)
		}
		return cfg.tunnel
	}
	anon := f.client(t, testWord, "")

	// Off: the endpoints are not there, for a right word as for a wrong one.
	if err := anon.Check(ctx); err == nil || !strings.Contains(err.Error(), "does not accept tunnels") {
		t.Fatalf("check with the hub off = %v", err)
	}
	if s := hub.snapshot(); s.Enabled || s.Anonymous || !s.Manage {
		t.Fatalf("snapshot = %+v", s)
	}

	// On, but serving still needs a token.
	if s := set(`{"enabled":true}`); !s.Enabled || s.Anonymous {
		t.Fatalf("after enabling = %+v", s)
	}
	if got := saved(); got == nil || !got.enabled || got.anonymous {
		t.Fatalf("saved after enabling = %+v", got)
	}
	if err := anon.Serve(ctx, "127.0.0.1:1"); err == nil || err.Error() != "access denied" {
		t.Fatalf("serve without a token = %v, want access denied", err)
	}

	// Anonymous serving on: no token needed, and the tunnel is listed
	// under the built-in tenant.
	if s := set(`{"anonymous":true}`); !s.Enabled || !s.Anonymous || len(s.Tenants) != 1 || !s.Tenants[0].Anonymous {
		t.Fatalf("after allowing anonymous serving = %+v", s)
	}
	if got := saved(); got == nil || !got.enabled || !got.anonymous {
		t.Fatalf("saved = %+v", got)
	}
	served := make(chan error, 1)
	go func() { served <- anon.Serve(ctx, echoTarget(t)) }()
	waitFor(t, "the anonymous word to be served", func() bool { return anon.Check(ctx) == nil })
	if w := hub.snapshot().Words[0]; w.Owner != anonymousOwner || !w.Live || w.Orphan {
		t.Fatalf("word = %+v", w)
	}
	// A wrong token is still wrong, and nobody takes the tunnel over.
	if err := f.client(t, otherWord, "not-a-serve-token-0123456789abcdefgh").Serve(ctx, "127.0.0.1:1"); err == nil || err.Error() != "access denied" {
		t.Fatalf("serve with an unknown token = %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+tunnel.Path+"/serve", nil)
	req.Header.Set(tunnel.HeaderWord, testWord)
	req.Header.Set(tunnel.HeaderName, "thief")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a second anonymous serve of a live word = %d, want 503", resp.StatusCode)
	}
	if anon.Check(ctx) != nil {
		t.Fatal("the tunnel did not survive the takeover attempt")
	}

	// Anonymous serving off: its tunnels end and their words are free.
	if s := set(`{"anonymous":false}`); s.Anonymous || len(s.Words) != 0 || len(s.Tenants) != 0 {
		t.Fatalf("after disallowing anonymous serving = %+v", s)
	}
	waitFor(t, "the anonymous tunnel to end", func() bool { return anon.Check(ctx) != nil })

	// Off again: a token's tunnel ends too, and stays bound.
	token, err := hub.addTenant("alice")
	if err != nil {
		t.Fatal(err)
	}
	alice := f.client(t, otherWord, token)
	go func() { _ = alice.Serve(ctx, echoTarget(t)) }()
	waitFor(t, "alice's word to be served", func() bool { return alice.Check(ctx) == nil })
	if s := set(`{"enabled":false}`); s.Enabled {
		t.Fatalf("after disabling = %+v", s)
	}
	if got := saved(); got == nil || got.enabled || len(got.tenants) != 1 {
		t.Fatalf("saved after disabling = %+v", got)
	}
	if err := alice.Check(ctx); err == nil || !strings.Contains(err.Error(), "does not accept tunnels") {
		t.Fatalf("check after disabling = %v", err)
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the anonymous serve did not stop")
	}

	// From the command line the switches are fixed.
	hub.persistSettings = nil
	on := true
	if err := hub.setSettings(&on, nil); !errors.Is(err, errSettingsFixed) {
		t.Fatalf("setSettings without a config file = %v", err)
	}
}

// A serving side that names a client token is only reached with it.
func TestRelayClientToken(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := f.client(t, testWord, testServeToken)
	server.ClientToken = "open sesame"[:4] + "-sesame"
	go func() { _ = server.Serve(ctx, echoTarget(t)) }()

	right := f.client(t, testWord, "")
	right.ClientToken = server.ClientToken
	waitFor(t, "the word to be served", func() bool { return right.Check(ctx) == nil })
	if w := f.hub.snapshot().Words[0]; !w.ClientToken {
		t.Fatalf("word = %+v", w)
	}
	for name, token := range map[string]string{"no": "", "a wrong": "open-sesame!"} {
		c := f.client(t, testWord, "")
		c.ClientToken = token
		if err := c.Check(ctx); err == nil || err.Error() != "access denied" {
			t.Fatalf("check with %s client token = %v, want access denied", name, err)
		}
		if err := c.ConnectOne(ctx, tunnel.Stdio{In: io.NopCloser(strings.NewReader("")), Out: nopWriteCloser{}}); err == nil || err.Error() != "access denied" {
			t.Fatalf("connect with %s client token = %v, want access denied", name, err)
		}
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- right.ConnectOne(ctx, tunnel.Stdio{In: inR, Out: outW}) }()
	go func() {
		_, _ = inW.Write([]byte("hello"))
		_ = inW.Close()
	}()
	if got, err := io.ReadAll(outR); err != nil || string(got) != "hello" {
		t.Fatalf("echo through a token-protected tunnel = %q, %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ConnectOne = %v", err)
	}
}

// The tunnel endpoints answer over https only: directly, or behind a proxy
// that says so.
func TestRelayHTTPSOnly(t *testing.T) {
	mgr := newManager(nil, nil, halfCloseIdleTimeout)
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, "")
	hub.denyDelay = 5 * time.Millisecond
	cs.tunnels = hub
	srv := httptest.NewServer(cs.handler()) // plain http
	defer srv.Close()
	check := func(proto string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+tunnel.Path+"/check", nil)
		req.Header.Set(tunnel.HeaderWord, testWord)
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := check(""); got != http.StatusBadRequest {
		t.Fatalf("plain http = %d, want 400", got)
	}
	if got := check("http"); got != http.StatusBadRequest {
		t.Fatalf("forwarded from http = %d, want 400", got)
	}
	if got := check("https"); got != http.StatusForbidden { // reached the hub: nobody serves the word
		t.Fatalf("forwarded from https = %d, want 403", got)
	}
}

// Tenants are added, rotated and deleted in the console and kept in the
// config file, which only ever holds the hash of a serve token.
func TestRelayTenants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.toml")
	// An empty [tunnel] is a hub with no tenants yet.
	if err := os.WriteFile(path, []byte("[console]\nlisten = \"18222\"\n\n[tunnel]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path, "")
	if err != nil || cfg.tunnel == nil || len(cfg.tunnel.tenants) != 0 {
		t.Fatalf("loadConfig = %+v, %v", cfg.tunnel, err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.tunnelRaw = cfg.configPath, cfg.consoleRaw, cfg.tunnelRaw
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(cfg.tunnel.tenants, halfCloseIdleTimeout, mgr.allocID, relayStatePath(path))
	hub.denyDelay, hub.persist = 5*time.Millisecond, mgr.saveTenants
	hub.guesses.limit = 1 << 30
	cs.tunnels = hub
	srv := httptest.NewTLSServer(cs.handler())
	defer func() {
		hub.closeAll()
		srv.CloseClientConnections()
		srv.Close()
	}()
	f := &relayFixture{hub: hub, srv: srv, tls: srv.Client().Transport.(*http.Transport).TLSClientConfig}

	post := func(url, body string) (int, map[string]string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/pf/api/relay/tenants"+url, strings.NewReader(body))
		req.Header.Set(csrfHeader, "1")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]string{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	status, out := post("", `{"name":"alice"}`)
	token := out["token"]
	if status != http.StatusOK || len(token) != newTokenLen || tunnel.CheckSecret("serve token", token) != nil {
		t.Fatalf("add = %d %v", status, out)
	}
	if status, _ := post("", `{"name":"alice"}`); status != http.StatusConflict {
		t.Fatalf("a duplicate name = %d, want 409", status)
	}
	if status, _ := post("", `{"name":"not ok"}`); status != http.StatusBadRequest {
		t.Fatalf("a bad name = %d, want 400", status)
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), token) || !strings.Contains(string(saved), tenantFor("alice", token).TokenSHA256) {
		t.Fatalf("the config file must hold the token's hash and not the token:\n%s", saved)
	}
	reloaded, err := loadConfig(path, "")
	if err != nil || reloaded.tunnel == nil || len(reloaded.tunnel.tenants) != 1 || reloaded.tunnel.tenants[0].Name != "alice" {
		t.Fatalf("reloaded = %+v, %v", reloaded.tunnel, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.client(t, testWord, token).Serve(ctx, "127.0.0.1:1")
	waitFor(t, "alice to serve her word", func() bool {
		w := hub.snapshot().Words
		return len(w) == 1 && w[0].Live && w[0].Owner == "alice"
	})
	// Nothing caps how many words she serves.
	go f.client(t, otherWord, token).Serve(ctx, "127.0.0.1:1")
	waitFor(t, "a second tunnel", func() bool { return hub.snapshot().Tenants[0].Live == 2 })

	// Rotating ends her tunnel and the old token; the word stays hers.
	status, out = post("/alice/rotate", "")
	if status != http.StatusOK || out["token"] == "" || out["token"] == token {
		t.Fatalf("rotate = %d %v", status, out)
	}
	waitFor(t, "her tunnels to end", func() bool { return hub.snapshot().Tenants[0].Live == 0 })
	cancel()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := f.client(t, testWord, token).Serve(ctx, "127.0.0.1:1"); err == nil || err.Error() != "access denied" {
		t.Fatalf("serve with the replaced token = %v", err)
	}
	go f.client(t, testWord, out["token"]).Serve(ctx, "127.0.0.1:1")
	waitFor(t, "alice to serve with her new token", func() bool { return hub.snapshot().Words[0].Live })

	// Deleting her ends the tunnel and frees the word.
	if status, _ := post("/alice/delete", ""); status != http.StatusNoContent {
		t.Fatalf("delete = %d", status)
	}
	if snap := hub.snapshot(); len(snap.Tenants) != 0 || len(snap.Words) != 0 || !snap.Manage {
		t.Fatalf("after delete: %+v", snap)
	}
	if status, _ := post("/alice/rotate", ""); status != http.StatusNotFound {
		t.Fatalf("rotate of a deleted tenant = %d, want 404", status)
	}
	if reloaded, err := loadConfig(path, ""); err != nil || reloaded.tunnel == nil || len(reloaded.tunnel.tenants) != 0 {
		t.Fatalf("the hub must stay on with no tenants left: %+v, %v", reloaded.tunnel, err)
	}

	// Tenants given on the command line cannot be changed.
	fixed := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, "")
	if _, err := fixed.addTenant("carol"); err != errTenantsFixed {
		t.Fatalf("add without a config file = %v", err)
	}
	if fixed.snapshot().Manage {
		t.Fatal("manage is on without a config file")
	}
}

func TestClientVersionMatches(t *testing.T) {
	src, err := os.ReadFile("cmd/pf-client/version.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"`+version+`"`) {
		t.Fatalf("cmd/pf-client/version.go does not carry version %s", version)
	}
}

// An address that keeps being refused is locked out before its next guess
// is looked at, so even the right word gets no answer; and a token that
// keeps binding new words loses the one it served longest ago.
func TestRelayGuessLimitAndWordLimit(t *testing.T) {
	f := newRelayFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.serveAndConnect(t, ctx, echoTarget(t))

	// Waiting for the word to be served was refused a few times already.
	f.hub.guesses.mu.Lock()
	clear(f.hub.guesses.seen)
	f.hub.guesses.limit = 3
	f.hub.guesses.mu.Unlock()
	wrong := f.client(t, otherWord, "")
	for i := 0; i < 3; i++ {
		if err := wrong.Check(ctx); err == nil || err.Error() != "access denied" {
			t.Fatalf("guess %d = %v, want access denied", i+1, err)
		}
	}
	for _, c := range []*tunnel.Client{wrong, f.client(t, testWord, "")} {
		if err := c.Check(ctx); err == nil || !strings.Contains(err.Error(), "too many refused attempts") {
			t.Fatalf("after the limit: %v, want a lock-out, for the right word too", err)
		}
	}
	f.hub.guesses.limit = 1 << 30
	if err := f.client(t, testWord, "").Check(ctx); err != nil {
		t.Fatalf("with the limit lifted: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	for addr, want := range map[string]string{
		"203.0.113.9:4000":      "203.0.113.9",
		"[2001:db8:1:2::9]:400": "2001:db8:1:2::",
	} {
		req.RemoteAddr = addr
		if got := sourceKey(req); got != want {
			t.Errorf("sourceKey(%s) = %s, want %s", addr, got, want)
		}
	}
	// Only a proxy on this host or network is believed about the client.
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.RemoteAddr = "203.0.113.9:4000"
	if got := sourceKey(req); got != "203.0.113.9" {
		t.Errorf("a direct client chose its own address: %s", got)
	}
	req.RemoteAddr = "127.0.0.1:4000"
	if got := sourceKey(req); got != "198.51.100.7" {
		t.Errorf("behind a local proxy: %s, want the forwarded address", got)
	}

	// alice holds testWord, live. With room for two words, a third pushes
	// out the idle one, never the live one.
	f.hub.maxWords = 2
	serveOnce := func(word string) {
		t.Helper()
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		go f.client(t, word, testServeToken).Serve(ctx, "127.0.0.1:1")
		live := func() bool {
			for _, w := range f.hub.snapshot().Words {
				if w.Word == word && w.Live {
					return true
				}
			}
			return false
		}
		waitFor(t, word+" to be served", live)
		stop()
		waitFor(t, word+" to go offline", func() bool { return !live() })
	}
	serveOnce("aaaa-aaaa-aaaa")
	serveOnce("bbbb-bbbb-bbbb")
	var words []string
	for _, w := range f.hub.snapshot().Words {
		words = append(words, w.Word)
	}
	if got := strings.Join(words, " "); got != testWord+" bbbb-bbbb-bbbb" {
		t.Fatalf("bound words = %q, want the live one and the newest", got)
	}
}
