package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
	"github.com/wushilin/pf-simple/pfrelay"
	"github.com/wushilin/pf-simple/pfrelayquic"
)

// withQUIC turns on the fixture hub's QUIC listener, on a free port of
// localhost.
func (f *relayFixture) withQUIC(t *testing.T) *quicHub {
	t.Helper()
	q := newQUICHub(f.hub, "")
	q.set = quicSettings{Enabled: true, Listen: "127.0.0.1:0", AdvertiseHost: "127.0.0.1", MaxConnections: 100, MaxBufferedMiB: 64}
	if err := q.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.stop)
	return q
}

// quicClient is f.client over QUIC.
func (f *relayFixture) quicClient(t *testing.T, word, serveToken string) *pfrelay.Client {
	t.Helper()
	c, err := pfrelayquic.NewClient(f.srv.URL, word, f.tls)
	if err != nil {
		t.Fatal(err)
	}
	c.ServeToken, c.Name = serveToken, "Test tunnel"
	if os.Getenv("PF_TEST_LOG") == "" {
		c.Logf = func(string, ...any) {}
	} else {
		c.Logf = t.Logf
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Every pairing of transports carries a connection, and the console says
// which transport the serving side uses.
func TestQUICPairings(t *testing.T) {
	for _, tc := range []struct {
		name         string
		serve, dial  bool // over QUIC
		wantTranport string
	}{
		{"quic serves, quic connects", true, true, "quic"},
		{"quic serves, ws connects", true, false, "quic"},
		{"ws serves, quic connects", false, true, "ws"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelayFixture(t, "")
			f.withQUIC(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mk := func(quic bool, token string) *pfrelay.Client {
				if quic {
					return f.quicClient(t, testWord, token)
				}
				return f.client(t, testWord, token)
			}
			server, dialer := mk(tc.serve, testServeToken), mk(tc.dial, "")
			go func() { _ = server.Serve(ctx, echoTarget(t)) }()
			waitFor(t, "the word to be served", func() bool { return dialer.Check(ctx) == nil })
			for i := 0; i < 3; i++ {
				if got := readAll(t, dialEcho(t, dialer)); got != "hello" {
					t.Fatalf("echo %d = %q", i, got)
				}
			}
			if w := f.wordSnap(t); w.Transport != tc.wantTranport {
				t.Errorf("transport %q, want %q", w.Transport, tc.wantTranport)
			}
		})
	}
}

// Discovery: who may ask, and what an old or QUIC-less hub answers.
func TestQUICDiscovery(t *testing.T) {
	f := newRelayFixture(t, "")
	q := f.withQUIC(t)
	ctx := context.Background()

	// A wrong word is refused at discovery, as check would.
	if err := f.quicClient(t, otherWord, "").Check(ctx); !errors.Is(err, pfrelay.ErrAccessDenied) {
		t.Errorf("check with a wrong word: %v", err)
	}
	// Serving with a wrong token is refused at discovery.
	bad := f.quicClient(t, testWord, "wrong-token-0123456789abcdefghijklmn")
	if err := bad.Serve(ctx, "127.0.0.1:1"); !errors.Is(err, pfrelay.ErrAccessDenied) {
		t.Errorf("serve with a wrong token: %v", err)
	}

	// No advertised host: 501, which is retried, not final.
	q.mu.Lock()
	q.set.AdvertiseHost = ""
	q.mu.Unlock()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+tunnel.Path+"/quic", nil)
	req.Header.Set(tunnel.HeaderOp, "serve")
	req.Header.Set(tunnel.HeaderServe, testServeToken)
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("no advertised host: %d", resp.StatusCode)
	}

	// A hub without QUIC answers the endpoint 404, as one from before 0.16
	// does: final, and said plainly.
	f2 := newRelayFixture(t, "")
	f2.hub.mu.Lock()
	f2.hub.enabled = false
	f2.hub.mu.Unlock()
	err = f2.quicClient(t, testWord, testServeToken).Serve(ctx, "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "does not offer QUIC") {
		t.Errorf("a hub without QUIC: %v", err)
	}
}

// A takeover over QUIC ends the old registration with the reason, and the
// old serving side registers again, as over WebSocket.
func TestQUICTakeoverEnds(t *testing.T) {
	f := newRelayFixture(t, "")
	f.withQUIC(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := f.quicClient(t, testWord, testServeToken)
	l, err := first.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	second := f.client(t, testWord, testServeToken)
	l2, err := second.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	// The first one comes back: the two take the word in turn.
	waitFor(t, "the QUIC side to take the word back", func() bool { return f.wordSnap(t).Transport == "quic" })
	_ = time.Second
}

// A certificate close to its end is replaced: discovery announces the new
// fingerprint and, for a while, the old one, and clients keep connecting.
func TestQUICCertificateRenewal(t *testing.T) {
	f := newRelayFixture(t, "")
	q := f.withQUIC(t)
	d, _ := q.discovery()
	old := d.Fingerprints[0]
	q.mu.Lock()
	leaf := leafOf(q.cert)
	q.mu.Unlock()
	if left := time.Until(leaf.NotAfter); left < 59*24*time.Hour || left > 61*24*time.Hour {
		t.Fatalf("a new certificate is valid for %s, want 60 days", left)
	}
	if dueForRenewal(q.cert) {
		t.Fatal("a new certificate is due for renewal")
	}
	q.renewIfDue() // not due: nothing changes
	if d, _ := q.discovery(); len(d.Fingerprints) != 1 || d.Fingerprints[0] != old {
		t.Fatalf("a certificate that is not due was replaced: %v", d.Fingerprints)
	}
	// Make it due: as if it had only 14 days left.
	q.mu.Lock()
	quicCertRenew = 61 * 24 * time.Hour
	q.mu.Unlock()
	q.renewIfDue()
	q.mu.Lock()
	quicCertRenew = 15 * 24 * time.Hour
	q.mu.Unlock()
	if d, _ := q.discovery(); len(d.Fingerprints) != 2 || d.Fingerprints[0] == old || d.Fingerprints[1] != old {
		t.Fatalf("after renewal discovery announces %v; want the new one, then %s", d.Fingerprints, old)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, dialer := f.quicClient(t, testWord, testServeToken), f.quicClient(t, testWord, "")
	go func() { _ = server.Serve(ctx, echoTarget(t)) }()
	waitFor(t, "the word to be served", func() bool { return dialer.Check(ctx) == nil })
	if got := readAll(t, dialEcho(t, dialer)); got != "hello" {
		t.Fatalf("echo = %q", got)
	}
}

// [tunnel.quic] is read from the config file, changed in the console, and
// saved; the console can replace the certificate.
func TestQUICSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n")
	cfg, err := loadConfig(path, "")
	if err != nil || cfg.tunnel.quic != defaultQUIC || cfg.tunnel.quic.Enabled {
		t.Fatalf("defaults = %+v, %v", cfg.tunnel.quic, err)
	}
	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n[tunnel.quic]\nenabled = true\nlisten = \"127.0.0.1:0\"\nadvertise_host = \"relay.example.com\"\nadvertise_port = 12354\n")
	if cfg, err = loadConfig(path, ""); err != nil {
		t.Fatal(err)
	}
	if q := cfg.tunnel.quic; !q.Enabled || q.Listen != "127.0.0.1:0" || q.AdvertiseHost != "relay.example.com" || q.AdvertisePort != 12354 || q.MaxConnections != defaultQUIC.MaxConnections {
		t.Fatalf("[tunnel.quic] = %+v", q)
	}
	for _, bad := range []string{"advertise_port = 70000", "advertise_host = \"[::1]\"", "enabled = true\nlisten = \"nonsense\""} {
		write("[console]\nlisten = \"18222\"\n\n[tunnel]\n[tunnel.quic]\n" + bad + "\n")
		if _, err := loadConfig(path, ""); err == nil || !strings.Contains(err.Error(), "[tunnel.quic]") {
			t.Errorf("%q: %v", bad, err)
		}
	}

	write("[console]\nlisten = \"18222\"\n\n[tunnel]\n")
	cfg, _ = loadConfig(path, "")
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.tunnelRaw = cfg.configPath, cfg.consoleRaw, cfg.tunnelRaw
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, relayStatePath(path))
	hub.persistSettings = mgr.saveTunnelSettings
	q := newQUICHub(hub, path)
	q.persist = mgr.saveTunnelQUIC
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
	post("relay/settings", `{"quic":{"enabled":true,"listen":"127.0.0.1:0","advertiseHost":"relay.example.com","advertisePort":0,"maxConnections":50,"maxBufferedMiB":8}}`, http.StatusOK)
	st := hub.snapshot().QUIC
	if st == nil || !st.Enabled || st.Listening == "" || len(st.Fingerprints) != 1 || st.ValidUntil == 0 {
		t.Fatalf("status after turning it on = %+v", st)
	}
	if cfg, err := loadConfig(path, ""); err != nil || !cfg.tunnel.quic.Enabled || cfg.tunnel.quic.MaxConnections != 50 || cfg.tunnel.quic.AdvertiseHost != "relay.example.com" {
		t.Fatalf("saved = %+v, %v", cfg.tunnel.quic, err)
	}
	if _, err := os.Stat(strings.TrimSuffix(path, ".toml") + ".quic-cert.pem"); err != nil {
		t.Errorf("the certificate is not kept beside the config: %v", err)
	}
	// Whole or nothing, and checked.
	post("relay/settings", `{"quic":{"enabled":true}}`, http.StatusBadRequest)
	post("relay/settings", `{"quic":{"enabled":true,"listen":"127.0.0.1:0","advertiseHost":"a b","advertisePort":0,"maxConnections":50,"maxBufferedMiB":8}}`, http.StatusBadRequest)
	old := st.Fingerprints[0]
	post("relay/quic/certificate", `{}`, http.StatusOK)
	if st := hub.snapshot().QUIC; len(st.Fingerprints) != 2 || st.Fingerprints[0] == old || st.Fingerprints[1] != old {
		t.Errorf("after replacing the certificate: %v", st.Fingerprints)
	}
	post("relay/settings", `{"quic":{"enabled":false,"listen":"127.0.0.1:0","advertiseHost":"relay.example.com","advertisePort":0,"maxConnections":50,"maxBufferedMiB":8}}`, http.StatusOK)
	if st := hub.snapshot().QUIC; st.Enabled || st.Listening != "" {
		t.Errorf("after turning it off = %+v", st)
	}
}
