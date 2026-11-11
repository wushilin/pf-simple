package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The own CA makes its keys once and only ever replaces certificates: when
// they are due, and when the server's names change.
func TestOwnCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	defer func() { tlsNow = time.Now }()
	start := time.Now()
	own := &ownCA{dir: dir, listenAddr: "0.0.0.0:18222", names: []string{"relay.example.com", "10.9.8.7"}}
	first, err := own.ensure()
	if err != nil {
		t.Fatal(err)
	}
	files := func() (caKey, caCrt, key, crt string) {
		return readFile(t, filepath.Join(dir, caKeyFile)), readFile(t, filepath.Join(dir, caCertFile)),
			readFile(t, filepath.Join(dir, leafKeyFile)), readFile(t, filepath.Join(dir, leafCertFile))
	}
	caKey0, caCrt0, key0, crt0 := files()
	for _, name := range []string{caKeyFile, leafKeyFile} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v; want mode 600", name, info, err)
		}
	}
	names := strings.Join(certNames(first.Leaf), ",")
	for _, want := range []string{"localhost", "127.0.0.1", "relay.example.com", "10.9.8.7"} {
		if !strings.Contains(","+names+",", ","+want+",") {
			t.Fatalf("certificate names %s lack %s", names, want)
		}
	}
	// It verifies against ca.crt alone, by a name it carries.
	verify := func(cert *tls.Certificate, caPEM string, at time.Time) error {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			t.Fatal("ca.crt holds no certificate")
		}
		_, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "relay.example.com", CurrentTime: at})
		return err
	}
	if err := verify(first, caCrt0, start); err != nil {
		t.Fatalf("the server certificate does not verify against the CA: %v", err)
	}

	// Nothing is due: nothing changes.
	if _, err := own.ensure(); err != nil {
		t.Fatal(err)
	}
	if a, b, c, d := files(); a != caKey0 || b != caCrt0 || c != key0 || d != crt0 {
		t.Fatal("a second look changed the files")
	}

	// Nine months on, the server certificate is renewed: same keys, same CA.
	tlsNow = func() time.Time { return start.Add(270 * 24 * time.Hour) }
	renewed, err := own.ensure()
	if err != nil {
		t.Fatal(err)
	}
	a, b, c, d := files()
	if a != caKey0 || c != key0 {
		t.Fatal("a renewal replaced a private key")
	}
	if b != caCrt0 {
		t.Fatal("the CA certificate was replaced long before it was due")
	}
	if d == crt0 || !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("the server certificate was not renewed")
	}
	if !samePublicKey(renewed.Leaf.PublicKey, first.Leaf.PublicKey) {
		t.Fatal("the renewed server certificate has another key")
	}
	crt1 := d

	// Nine years on, the CA certificate is renewed too, with the same key
	// and name: a client that kept the first ca.crt still trusts the server
	// while that copy is valid, and one with the new copy trusts it too.
	late := start.Add(9 * 365 * 24 * time.Hour)
	tlsNow = func() time.Time { return late }
	last, err := own.ensure()
	if err != nil {
		t.Fatal(err)
	}
	a, b, c, d = files()
	if a != caKey0 || c != key0 {
		t.Fatal("renewing the CA replaced a private key")
	}
	if b == caCrt0 || d == crt1 {
		t.Fatal("the certificates were not renewed")
	}
	if err := verify(last, caCrt0, late); err != nil {
		t.Fatalf("a client with the first ca.crt no longer trusts the server: %v", err)
	}
	if err := verify(last, b, late); err != nil {
		t.Fatalf("a client with the new ca.crt does not trust the server: %v", err)
	}

	// Other names: issued again, same key.
	own.names = []string{"other.example.com"}
	again, err := own.ensure()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(certNames(again.Leaf), ","); !strings.Contains(got, "other.example.com") || strings.Contains(got, "relay.example.com") {
		t.Fatalf("names after the change: %s", got)
	}
	if _, _, key, _ := files(); key != key0 {
		t.Fatal("new names replaced the private key")
	}

	// A key that cannot be read is reported, never replaced.
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := own.ensure(); err == nil || !strings.Contains(err.Error(), "fix or remove") {
		t.Fatalf("ensure with a broken CA key = %v", err)
	}
	if got := readFile(t, filepath.Join(dir, caKeyFile)); got != "garbage" {
		t.Fatal("the broken key was overwritten")
	}
}

// With its own TLS the console needs no proxy: pf-client reaches the hub
// directly and trusts it through ca.pem. The mode is switched while the
// listener stays up, and kept in the config file.
func TestConsoleOwnTLS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.toml")
	if err := os.WriteFile(path, []byte("[console]\nlisten = \"127.0.0.1:18222\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path, "")
	if err != nil || cfg.console.tlsMode != tlsOff {
		t.Fatalf("loadConfig = %+v, %v", cfg.console, err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.tunnelRaw = cfg.configPath, cfg.consoleRaw, cfg.tunnelRaw
	cs := newConsoleServer("", "", mgr)
	hub := newTunnelHub(testTenants(), halfCloseIdleTimeout, mgr.allocID, "")
	hub.denyDelay = 5 * time.Millisecond
	hub.guesses.limit = 1 << 30
	cs.tunnels = hub
	cs.tls = newTLSManager(cfg.console.addr, path)
	cs.tls.persist = mgr.saveConsoleTLS
	if err := cs.tls.start(cfg.console.tlsMode, cfg.console.tlsDir, cfg.console.tlsNames); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: cs.handler()}
	go func() { _ = srv.Serve(cs.tls.listen(ln)) }()
	defer srv.Close()
	defer hub.closeAll()
	addr := ln.Addr().String()

	// post sends the settings over whatever the listener speaks now. Each
	// request is a new connection, as after a page reload.
	post := func(client *http.Client, scheme, body string) (int, tlsState) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/pf/api/tls", strings.NewReader(body))
		req.Header.Set(csrfHeader, "1")
		req.Close = true
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var st tlsState
		_ = json.NewDecoder(resp.Body).Decode(&st)
		return resp.StatusCode, st
	}
	saved := func() *consoleSettings {
		t.Helper()
		cfg, err := loadConfig(path, "")
		if err != nil {
			t.Fatal(err)
		}
		return cfg.console
	}
	plain := &http.Client{}

	// A directory without a certificate is refused, and nothing changes.
	if code, _ := post(plain, "http", `{"mode":"directory","dir":"mine"}`); code != http.StatusBadRequest {
		t.Fatalf("directory mode without files = %d, want 400", code)
	}
	if code, _ := post(plain, "http", `{"mode":"sideways"}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown mode = %d, want 400", code)
	}
	if got := saved(); got.tlsMode != tlsOff {
		t.Fatalf("saved after refusals = %+v", got)
	}

	// Self-signed, in a directory of the user's choosing.
	code, st := post(plain, "http", `{"mode":"self_signed","dir":"mine","names":["relay.example.com"]}`)
	if code != http.StatusOK || st.Mode != tlsSelfSigned || st.Path != filepath.Join(dir, "mine") || st.Fingerprint == "" || !st.Manage {
		t.Fatalf("turning self_signed on = %d, %+v", code, st)
	}
	if got := saved(); got.tlsMode != tlsSelfSigned || got.tlsDir != "mine" || len(got.tlsNames) != 1 {
		t.Fatalf("saved = %+v", got)
	}
	caPEM := readFile(t, filepath.Join(dir, "mine", caCertFile))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("ca.pem holds no certificate")
	}
	trusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	// pf-client now reaches the hub directly, trusting the CA.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url := "https://" + addr
	server, err := tunnel.NewClient(url, testWord, &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	server.ServeToken, server.Name, server.Logf = testServeToken, "Direct", func(string, ...any) {}
	go func() { _ = server.Serve(ctx, echoTarget(t)) }()
	client, err := tunnel.NewClient(url, testWord, &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	client.Logf = func(string, ...any) {}
	waitFor(t, "the word to be served over the console's own TLS", func() bool { return client.Check(ctx) == nil })
	// Without the CA the certificate is not trusted.
	stranger, _ := tunnel.NewClient(url, testWord, nil)
	if err := stranger.Check(ctx); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("check without the CA = %v", err)
	}
	// Plain http to the port gets nowhere near the hub.
	if resp, err := http.Get("http://" + addr + tunnel.Path + "/check"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plain http on the TLS port = %d", resp.StatusCode)
		}
	}

	// The user's own files: copy what the CA made into another directory.
	theirs := filepath.Join(dir, "theirs")
	if err := os.Mkdir(theirs, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{leafCertFile, leafKeyFile} {
		if err := os.WriteFile(filepath.Join(theirs, name), []byte(readFile(t, filepath.Join(dir, "mine", name))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, st = post(trusting, "https", `{"mode":"directory","dir":"`+theirs+`"}`)
	if code != http.StatusOK || st.Mode != tlsDirectory || st.Path != theirs || st.Fingerprint == "" {
		t.Fatalf("directory mode = %d, %+v", code, st)
	}
	if _, err := os.Stat(filepath.Join(theirs, caKeyFile)); err == nil {
		t.Fatal("directory mode made a CA in the user's directory")
	}

	// Off again: plain http answers, and the file no longer mentions tls.
	if code, st := post(trusting, "https", `{"mode":"off"}`); code != http.StatusOK || st.Mode != tlsOff || st.Fingerprint != "" {
		t.Fatalf("turning it off = %d, %+v", code, st)
	}
	if strings.Contains(readFile(t, path), "tls =") {
		t.Fatalf("the config still says tls:\n%s", readFile(t, path))
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/pf/api/tls", nil)
	req.Close = true
	resp, err := plain.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("plain http after turning TLS off: %v", err)
	}
	resp.Body.Close()

	// From the command line the settings are fixed.
	cs.tls.persist = nil
	if code, _ := post(plain, "http", `{"mode":"self_signed"}`); code != http.StatusForbidden {
		t.Fatalf("changing TLS without a config file = %d, want 403", code)
	}
}

// In directory mode the files are read again when they change.
func TestCertFilesReload(t *testing.T) {
	dir := t.TempDir()
	a := &ownCA{dir: filepath.Join(dir, "a"), listenAddr: "127.0.0.1:1"}
	b := &ownCA{dir: filepath.Join(dir, "b"), listenAddr: "127.0.0.1:1"}
	certA, err := a.ensure()
	if err != nil {
		t.Fatal(err)
	}
	certB, err := b.ensure()
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "live")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatal(err)
	}
	put := func(from string, when time.Time) {
		for _, name := range []string{leafCertFile, leafKeyFile} {
			dst := filepath.Join(live, name)
			if err := os.WriteFile(dst, []byte(readFile(t, filepath.Join(dir, from, name))), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(dst, when, when); err != nil {
				t.Fatal(err)
			}
		}
	}
	put("a", time.Now().Add(-time.Hour))
	files := &certFiles{certPath: filepath.Join(live, leafCertFile), keyPath: filepath.Join(live, leafKeyFile)}
	if _, err := files.load(); err != nil {
		t.Fatal(err)
	}
	if got, _ := files.get(nil); tunnel.Fingerprint(got.Leaf) != tunnel.Fingerprint(certA.Leaf) {
		t.Fatal("not the certificate in the files")
	}
	// A change is not looked for again within certRecheck...
	put("b", time.Now())
	if got, _ := files.get(nil); tunnel.Fingerprint(got.Leaf) != tunnel.Fingerprint(certA.Leaf) {
		t.Fatal("the files were read again too soon")
	}
	// ...and is picked up after it.
	due := func() {
		files.mu.Lock()
		files.checked = time.Time{}
		files.mu.Unlock()
	}
	due()
	if got, _ := files.get(nil); tunnel.Fingerprint(got.Leaf) != tunnel.Fingerprint(certB.Leaf) {
		t.Fatal("the changed files were not picked up")
	}
	// A broken change keeps the certificate in use.
	if err := os.WriteFile(files.certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	due()
	if got, err := files.get(nil); err != nil || tunnel.Fingerprint(got.Leaf) != tunnel.Fingerprint(certB.Leaf) {
		t.Fatalf("after a broken change: %v", err)
	}
}

func TestConsoleTLSSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.toml")
	load := func(console string) (settings, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte("[console]\nlisten = \"18222\"\n"+console), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(path, "")
	}
	if s, err := load(""); err != nil || s.console.tlsMode != tlsOff {
		t.Fatalf("no tls keys: %+v, %v", s.console, err)
	}
	if s, err := load("tls = \"self_signed\"\ntls_dir = \"asdf123\"\ntls_names = [\"relay.example.com\", \"10.0.0.5\"]\n"); err != nil || s.console.tlsMode != tlsSelfSigned || s.console.tlsDir != "asdf123" || len(s.console.tlsNames) != 2 {
		t.Fatalf("self_signed: %+v, %v", s.console, err)
	}
	if s, err := load("tls = \"directory\"\n"); err != nil || s.console.tlsMode != tlsDirectory || s.console.tlsDir != "" {
		t.Fatalf("directory: %+v, %v", s.console, err)
	}
	if _, err := load("tls = \"yes\"\n"); err == nil || !strings.Contains(err.Error(), "self_signed") {
		t.Fatalf("an unknown mode = %v", err)
	}
	if _, err := load("tls = \"self_signed\"\ntls_names = [\"not a name\"]\n"); err == nil {
		t.Fatal("a bad tls_names entry was accepted")
	}
	if s, err := parseArgs([]string{"--console", "18222", "--console-tls", "8080@10.0.0.1:80"}, os.Stderr, ""); err != nil || s.console.tlsMode != tlsSelfSigned {
		t.Fatalf("--console-tls: %+v, %v", s.console, err)
	}
	if _, err := parseArgs([]string{"--console-tls", "8080@10.0.0.1:80"}, os.Stderr, ""); err == nil {
		t.Fatal("--console-tls without --console was accepted")
	}
	// A relative tls_dir is next to the config file; the default is certs.
	m := newTLSManager("127.0.0.1:1", path)
	if got := m.resolve(""); got != filepath.Join(filepath.Dir(path), "certs") {
		t.Fatalf("default directory = %s", got)
	}
	if got := m.resolve("/etc/pf/certs"); got != "/etc/pf/certs" {
		t.Fatalf("absolute directory = %s", got)
	}
}
