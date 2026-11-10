package tunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Serve retries for ever: 1s, 2s, 4s ... up to 30s, starting over only once
// a control channel has lasted a minute. The test runs the same schedule 50
// times faster: 20ms doubling to 160ms, starting over after 400ms.
func TestServeBackoff(t *testing.T) {
	defer func(a, b, c time.Duration) { retryMin, retryMax, settled = a, b, c }(retryMin, retryMax, settled)
	retryMin, retryMax, settled = 20*time.Millisecond, 160*time.Millisecond, 400*time.Millisecond

	// What the relay does with each registration, in order; after the
	// script runs out it holds the channel open.
	script := []string{
		"down", "down", // not reachable when serve starts: 502s from a proxy
		"drop", "drop", "drop", "drop", "drop", // comes up and drops straight away
		"hold", // up for longer than settled, then lost
		"drop",
	}
	var mu sync.Mutex
	var attempts []time.Time
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := len(attempts)
		attempts = append(attempts, time.Now())
		mu.Unlock()
		step := "open"
		if n < len(script) {
			step = script[n]
		}
		if step == "down" {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		ws, err := Upgrade(w, r, nil)
		if err != nil {
			return
		}
		switch step {
		case "hold":
			time.Sleep(settled + 100*time.Millisecond)
		case "open":
			_ = ws.ReadLoop()
		}
		_ = ws.Close()
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "k3f9-x2mq-7hpa", srv.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	c.ServeToken, c.Name = strings.Repeat("t", MinSecret), "test"
	c.Logf = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, "127.0.0.1:1") }()

	deadline := time.Now().Add(15 * time.Second)
	for {
		mu.Lock()
		n := len(attempts)
		mu.Unlock()
		if n > len(script) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d registrations in 15s; serve gave up or stalled", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v; it must only stop when told to", err)
	}

	// The pause before each registration, after the one before it ended.
	// "hold" lasts settled+100ms itself, so its gap is measured from there.
	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{20, 40, 80, 160, 160, 160, 160, 0, 20, 40}
	for i := 1; i <= len(script); i++ {
		gap := attempts[i].Sub(attempts[i-1])
		if script[i-1] == "hold" {
			gap -= settled + 100*time.Millisecond
		}
		lo := want[i-1] * time.Millisecond
		if i-1 == 7 {
			continue // the registration that is held; its own pause is want[6], checked above
		}
		if gap < lo-5*time.Millisecond || gap > lo+150*time.Millisecond {
			t.Errorf("pause before registration %d (after %q) = %s, want about %s", i+1, script[i-1], gap.Round(time.Millisecond), lo)
		}
	}
}

// A refusal of the very first registration is a mistake to report, not to
// retry.
func TestServeFirstRefusalIsFinal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "k3f9-x2mq-7hpa", srv.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	c.ServeToken, c.Name = strings.Repeat("t", MinSecret), "test"
	c.Logf = func(string, ...any) {}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Serve(ctx, "127.0.0.1:1"); err == nil || err.Error() != "access denied" {
		t.Fatalf("Serve = %v, want access denied", err)
	}
}

// Watch says when the tunnel comes up and when it goes away, and nothing in
// between.
func TestWatch(t *testing.T) {
	defer func(a, b, c time.Duration) { retryMin, retryMax, recheck = a, b, c }(retryMin, retryMax, recheck)
	retryMin, retryMax, recheck = 10*time.Millisecond, 40*time.Millisecond, 10*time.Millisecond

	var mu sync.Mutex
	up := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if up {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "k3f9-x2mq-7hpa", srv.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 100)
	c.Logf = func(format string, args ...any) { lines <- format }
	ctx, cancel := context.WithCancel(context.Background())
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		c.Watch(ctx)
	}()
	defer func() { // before the timing is put back
		cancel()
		<-watching
	}()

	expect := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if !strings.Contains(got, want) {
				t.Fatalf("logged %q, want something about %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("nothing logged about %q", want)
		}
	}
	set := func(v bool) {
		mu.Lock()
		up = v
		mu.Unlock()
	}
	expect("not available")
	time.Sleep(150 * time.Millisecond) // many failed checks: no more lines
	set(true)
	expect("is up")
	time.Sleep(100 * time.Millisecond) // many good checks: no more lines
	set(false)
	expect("not available")
	set(true)
	expect("is up")
}
