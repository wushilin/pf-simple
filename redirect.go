package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// httpRedirectAddr is where enable_http_to_https_redirect listens.
const httpRedirectAddr = ":80"

// addRedirect appends the HTTP-to-HTTPS redirect as a listener. It goes after
// the forwards, so a [[forward]] on port 80 binds first; a bind failure shows
// as "failed to start" in the console and never stops pf-simple.
func (m *manager) addRedirect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := newListenerStats(0, httpRedirectAddr, "https://<same host and path>")
	stats.name = "HTTP to HTTPS redirect"
	m.appendLocked(stats, sourceRedirect, true)
}

// serveHTTPRedirect answers every request on ln with a redirect to the same
// host and path over https until ctx ends. Each connection carries one
// redirect and is closed after it, so l's accepted counter counts redirects
// and l.active is what the console shows as active.
func serveHTTPRedirect(ctx context.Context, ln net.Listener, l *listenerStats) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(redirectToHTTPS),
		ReadHeaderTimeout: 10 * time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				l.accepted.Add(1)
				l.active.Add(1)
			case http.StateClosed, http.StateHijacked:
				l.active.Add(-1)
			default:
				return
			}
			changes.notify()
		},
	}
	srv.SetKeepAlivesEnabled(false)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		log.Printf("http-to-https redirect: %v", err)
	}
}

// redirectToHTTPS sends the client to https on the default port, keeping the
// host, path and query, and logs one line per request. GET and HEAD get 301;
// other methods get 308 so the method and body are kept.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		log.Printf("redirect %s %s %s: missing Host header (400)", r.RemoteAddr, r.Method, r.URL.RequestURI())
		http.Error(w, "missing Host header", http.StatusBadRequest)
		return
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	code := http.StatusPermanentRedirect
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		code = http.StatusMovedPermanently
	}
	target := "https://" + host + r.URL.RequestURI()
	log.Printf("redirect %s %s http://%s%s -> %s (%d)", r.RemoteAddr, r.Method, r.Host, r.URL.RequestURI(), target, code)
	http.Redirect(w, r, target, code)
}
