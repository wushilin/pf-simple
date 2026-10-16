package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed console
var consoleFiles embed.FS

const (
	// sessionCookiePrefix plus the console's port names the session cookie.
	// Browsers share cookies across ports of one host, so two consoles on the
	// same machine would otherwise sign each other out.
	sessionCookiePrefix = "pf_session_"
	sessionLifetime     = 12 * time.Hour
	// csrfHeader must accompany every state-changing request. Browsers cannot
	// add custom headers to cross-site form posts, and SameSite=Strict keeps
	// the cookie off cross-site requests as a second layer.
	csrfHeader = "X-PF-Console"

	// pushInterval caps pushes at one per 100ms while traffic flows. When
	// nothing changes, nothing is sent.
	pushInterval   = 100 * time.Millisecond
	wsPingInterval = 30 * time.Second
)

// parseConsole splits "listen-address[@password]". A bare port binds to
// 127.0.0.1. An empty password falls back to envPassword; if both are empty
// the console has no password.
func parseConsole(value, envPassword string) (addr, password string, err error) {
	addr, password, _ = strings.Cut(value, "@")
	addr, err = normalizeListen(addr, "127.0.0.1")
	if err != nil {
		return "", "", fmt.Errorf("console: %w", err)
	}
	if password == "" {
		password = envPassword
	}
	return addr, password, nil
}

type consoleServer struct {
	addr       string
	host       string
	password   string
	started    time.Time
	mgr        *manager
	cookieName string

	ctx context.Context // canceled on shutdown; ends WebSocket sessions

	mu       sync.Mutex
	sessions map[string]time.Time // token -> expiry

	subMu       sync.Mutex
	subscribers map[chan struct{}]struct{}
}

func newConsoleServer(addr, password string, mgr *manager) *consoleServer {
	host, _ := os.Hostname()
	s := &consoleServer{
		addr:        addr,
		host:        host,
		password:    password,
		started:     time.Now(),
		ctx:         context.Background(),
		sessions:    make(map[string]time.Time),
		subscribers: make(map[chan struct{}]struct{}),
	}
	s.mgr = mgr
	return s
}

func (s *consoleServer) handler() http.Handler {
	static, _ := fs.Sub(consoleFiles, "console")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/login", s.requireCSRF(s.handleLogin))
	mux.HandleFunc("POST /api/logout", s.requireCSRF(s.handleLogout))
	mux.HandleFunc("GET /api/state", s.requireAuth(s.handleState))
	mux.HandleFunc("GET /api/ws", s.requireAuth(s.handleWebSocket))
	mux.HandleFunc("POST /api/listeners", s.requireCSRF(s.requireAuth(s.handleAddListener)))
	mux.HandleFunc("POST /api/listeners/{id}/{action}", s.requireCSRF(s.requireAuth(s.handleListenerAction)))
	mux.HandleFunc("POST /api/pipes/{id}/stop", s.requireCSRF(s.requireAuth(s.handleStop)))
	return securityHeaders(mux)
}

func (s *consoleServer) serve(ctx context.Context, ln net.Listener) {
	s.ctx = ctx
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.cookieName = sessionCookiePrefix + port
	go s.broadcast(ctx)
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("console: %v", err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *consoleServer) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != "1" {
			http.Error(w, "missing "+csrfHeader+" header", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *consoleServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *consoleServer) authorized(r *http.Request) bool {
	if s.password == "" {
		return true
	}
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[cookie.Value]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, cookie.Value)
		return false
	}
	return true
}

func (s *consoleServer) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{
		"passwordRequired": s.password != "",
		"authorized":       s.authorized(r),
	})
}

func (s *consoleServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.password != "" {
		// Compare hashes so the comparison time does not depend on length.
		got, want := sha256.Sum256([]byte(body.Password)), sha256.Sum256([]byte(s.password))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			time.Sleep(time.Second) // slow down guessing
			http.Error(w, "wrong password", http.StatusUnauthorized)
			return
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(raw[:])
	now := time.Now()
	s.mu.Lock()
	for t, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, t)
		}
	}
	s.sessions[token] = now.Add(sessionLifetime)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionLifetime / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *consoleServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

type consoleState struct {
	Host      string             `json:"host"`
	Now       int64              `json:"now"`
	Started   int64              `json:"started"`
	Listeners []listenerSnapshot `json:"listeners"`
	Manage    manageInfo         `json:"manage"`
}

func (s *consoleServer) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.state())
}

func (s *consoleServer) handleStop(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad connection id", http.StatusBadRequest)
		return
	}
	p := pipes.get(id)
	if p == nil {
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	}
	p.interrupt()
	log.Printf("console: reset pipe #%d %s -> %s", id, p.client.RemoteAddr(), p.listener.target)
	w.WriteHeader(http.StatusNoContent)
}

// broadcast wakes every WebSocket session when the registry or any counter
// changed, at most once per pushInterval. It blocks while nothing changes.
func (s *consoleServer) broadcast(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes.wake:
		}
		changes.dirty.Store(false) // changes from here on wake the next round
		s.subMu.Lock()
		for ch := range s.subscribers {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		s.subMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(pushInterval):
		}
	}
}

func (s *consoleServer) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.subMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subMu.Unlock()
	return ch
}

func (s *consoleServer) unsubscribe(ch chan struct{}) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	s.subMu.Unlock()
}

func (s *consoleServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	defer ws.Close()
	updates := s.subscribe()
	defer s.unsubscribe(updates)

	gone := make(chan struct{})
	go func() {
		_ = ws.readLoop()
		close(gone)
	}()
	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()

	send := func() error {
		data, err := json.Marshal(s.state())
		if err != nil {
			return err
		}
		return ws.writeFrame(wsOpText, data)
	}
	if send() != nil {
		return
	}
	for {
		select {
		case <-s.ctx.Done():
			_ = ws.writeFrame(wsOpClose, []byte{0x03, 0xE9}) // 1001 going away
			return
		case <-gone:
			return
		case <-ping.C:
			if ws.writeFrame(wsOpPing, nil) != nil {
				return
			}
		case <-updates:
			if send() != nil {
				return
			}
		}
	}
}

func (s *consoleServer) state() consoleState {
	return consoleState{
		Host:      s.host,
		Now:       time.Now().UnixMilli(),
		Started:   s.started.UnixMilli(),
		Listeners: s.mgr.snapshot(),
		Manage:    s.mgr.info(),
	}
}

func (s *consoleServer) handleAddListener(w http.ResponseWriter, r *http.Request) {
	var spec listenerSpec
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	id, err := s.mgr.add(spec)
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	log.Printf("console: added listener #%d %s -> %s", id, spec.Listen, spec.Target)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]int{"id": id})
}

func (s *consoleServer) handleListenerAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad listener id")
		return
	}
	switch r.PathValue("action") {
	case "start":
		err = s.mgr.start(id)
	case "stop":
		err = s.mgr.stop(id)
	case "delete":
		err = s.mgr.remove(id)
	case "edit":
		var spec listenerSpec
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&spec); derr != nil {
			writeError(w, http.StatusBadRequest, "bad request: "+derr.Error())
			return
		}
		err = s.mgr.edit(id, spec)
	default:
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	if err != nil {
		writeError(w, statusFor(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, errNotFound):
		return http.StatusNotFound
	case errors.Is(err, errReadOnly), errors.Is(err, errNoManaging):
		return http.StatusForbidden
	case errors.Is(err, errRunning):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
