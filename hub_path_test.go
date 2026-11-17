package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/wushilin/pf-simple/pfrelay"
)

// A hub at a path of its own answers nothing outside it: not the root, not
// /pf, not the health check. Clients that give the path work, over
// WebSocket and over QUIC; clients that do not are refused.
func TestHubAtItsOwnPath(t *testing.T) {
	const prefix = "/xzfe-aeeg-e2da"
	f := newRelayFixture(t, "")
	f.withQUIC(t)
	f.mount(prefix)
	httpc := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: f.tls},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	status := func(path string) int {
		t.Helper()
		r, err := httpc.Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	for _, path := range []string{"/", "/pf", "/pf/", "/pf/index.html", "/pf/api/health", "/pf/api/tunnel/check", "/pf/api/tunnel/quic", "/api/health", "/xzfe-aeeg-e2da-x/"} {
		if code := status(path); code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, code)
		}
	}
	for _, path := range []string{prefix + "/", prefix + "/api/health"} {
		if code := status(path); code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", path, code)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = f.client(t, testWord, testServeToken).Serve(ctx, echoTarget(t)) }()
	ws := f.client(t, testWord, "")
	waitFor(t, "the tunnel to be served", func() bool { return ws.Check(ctx) == nil })
	if got := readAll(t, dialEcho(t, ws)); got != "hello" {
		t.Errorf("over WebSocket: echoed %q", got)
	}
	if got := readAll(t, dialEcho(t, f.quicClient(t, testWord, ""))); got != "hello" {
		t.Errorf("over QUIC: echoed %q", got)
	}

	// The same server without the path is not a hub.
	for _, base := range []string{f.srv.URL, f.srv.URL + "/pf/"} {
		c, err := pfrelay.NewClient(base, testWord, f.tls)
		if err != nil {
			t.Fatal(err)
		}
		c.Logf = func(string, ...any) {}
		if err := c.Check(ctx); err == nil {
			t.Errorf("check through %s succeeded", base)
		}
	}
}
