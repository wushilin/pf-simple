package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRedirectToHTTPS(t *testing.T) {
	cases := []struct {
		method, host, target string
		code                 int
		want                 string
	}{
		{"GET", "example.com", "/a/b?x=1&y=2", 301, "https://example.com/a/b?x=1&y=2"},
		{"HEAD", "example.com:80", "/", 301, "https://example.com/"},
		{"POST", "example.com", "/form", 308, "https://example.com/form"},
		{"GET", "[2001:db8::1]:80", "/v6", 301, "https://[2001:db8::1]/v6"},
		{"GET", "10.0.0.6", "/%2Fenc", 301, "https://10.0.0.6/%2Fenc"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://placeholder"+c.target, nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		redirectToHTTPS(w, r)
		if w.Code != c.code || w.Header().Get("Location") != c.want {
			t.Errorf("%s %s%s: got %d %q, want %d %q", c.method, c.host, c.target, w.Code, w.Header().Get("Location"), c.code, c.want)
		}
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = ""
	w := httptest.NewRecorder()
	redirectToHTTPS(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing host: got %d", w.Code)
	}
}

func TestRedirectConfigDefault(t *testing.T) {
	fwd := "[[forward]]\nlisten = \"127.0.0.1:2\"\ntarget = \"127.0.0.1:3\"\n"
	for body, want := range map[string]bool{
		fwd: true,
		"enable_http_to_https_redirect = true\n" + fwd:  true,
		"enable_http_to_https_redirect = false\n" + fwd: false,
	} {
		s, err := loadConfig(writeConfig(t, body), "")
		if err != nil || s.httpRedirect != want {
			t.Errorf("config %q: httpRedirect=%v err=%v, want %v", body, s.httpRedirect, err, want)
		}
	}
	if s, err := parseArgs([]string{"8080@10.0.0.6"}, os.Stderr, ""); err != nil || s.httpRedirect {
		t.Errorf("command line mode must not redirect: %+v %v", s, err)
	}
}

func TestSaveKeepsRedirectSetting(t *testing.T) {
	path := writeConfig(t, "enable_http_to_https_redirect = false\n[console]\nlisten = \"127.0.0.1:1\"\n")
	cfg, err := loadConfig(path, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr := newManager(cfg.forwards, cfg.console.manage, halfCloseIdleTimeout)
	mgr.configPath, mgr.consoleRaw, mgr.redirectRaw = cfg.configPath, cfg.consoleRaw, cfg.redirectRaw
	if err := mgr.saveLocked(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "enable_http_to_https_redirect = false") {
		t.Fatalf("saved file lost the setting:\n%s", data)
	}
	if cfg, err = loadConfig(path, ""); err != nil || cfg.httpRedirect {
		t.Fatalf("reload: httpRedirect=%v err=%v", cfg.httpRedirect, err)
	}
}

func TestRedirectListener(t *testing.T) {
	mgr := newManager(nil, nil, halfCloseIdleTimeout)
	mgr.addRedirect()
	ml := mgr.list[0]
	ml.stats.listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := mgr.startAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer mgr.shutdown()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get("http://" + ml.stats.listen + "/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "https://127.0.0.1/x?y=1"
	if resp.StatusCode != 301 || resp.Header.Get("Location") != want {
		t.Fatalf("got %d %q, want 301 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	if snap := snapshotFor(mgr, ml.stats.id); !snap.Running || snap.Source != sourceRedirect {
		t.Fatalf("snapshot: %+v", snap)
	}
	if err := mgr.stop(ml.stats.id); err != nil {
		t.Fatal(err)
	}

	// A taken port never fails startup, even without a console; the error
	// shows on the listener instead.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	mgr2 := newManager(nil, nil, halfCloseIdleTimeout)
	mgr2.addRedirect()
	mgr2.list[0].stats.listen = busy.Addr().String()
	if err := mgr2.startAll(context.Background()); err != nil {
		t.Fatalf("busy port must not stop startup: %v", err)
	}
	defer mgr2.shutdown()
	if snap := snapshotFor(mgr2, 0); snap.Running || snap.Error == "" {
		t.Fatalf("busy port should show an error: %+v", snap)
	}
}

func TestRedirectListenerNotEditable(t *testing.T) {
	policy, _ := newManagePolicy(&consoleTable{})
	mgr := newManager(nil, policy, halfCloseIdleTimeout)
	mgr.addRedirect()
	if err := mgr.remove(0); err != errRedirect {
		t.Errorf("delete: %v", err)
	}
	if err := mgr.edit(0, listenerSpec{Listen: "2000", Target: "x"}); err != errRedirect {
		t.Errorf("edit: %v", err)
	}
}
