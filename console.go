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
	"sync/atomic"
	"time"

	queue "github.com/wushilin/go-named-queue"
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
	// apiTokenHeader carries the console password for scripts, instead of a
	// session cookie. Being a custom header, it also satisfies the CSRF check.
	apiTokenHeader = "X-API-Token"

	// pushInterval is the emitter's tick: at most one push per 400ms, and
	// none at all while nothing changes.
	pushInterval = 400 * time.Millisecond

	// stateQueue is the broadcast queue every console tab subscribes to. Each
	// push is marshaled once and delivered to all subscribers; it holds at
	// most stateQueueCapacity frames and drops the oldest when full, so a slow
	// tab misses stale frames instead of holding the others back.
	stateQueue         = "console.state"
	stateQueueCapacity = 8
	wsPingInterval     = 30 * time.Second
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

type consoleSession struct {
	expires time.Time
	revoked chan struct{} // closed under consoleServer.mu on logout or expiry
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
	sessions map[string]*consoleSession // token -> session

	pushEvery time.Duration // pushInterval; tests shorten it
	queues    *queue.QueueRegistry
	frames    *queue.Sender[[]byte]
	viewers   atomic.Int32 // subscribed tabs; nothing is marshaled while zero
}

func newConsoleServer(addr, password string, mgr *manager) *consoleServer {
	host, _ := os.Hostname()
	s := &consoleServer{
		addr:      addr,
		host:      host,
		password:  password,
		started:   time.Now(),
		ctx:       context.Background(),
		sessions:  make(map[string]*consoleSession),
		pushEvery: pushInterval,
		queues:    queue.NewRegistry(),
	}
	if err := queue.CreateBroadcastingWithFullAction[[]byte](s.queues, stateQueue, stateQueueCapacity, queue.FullDropOldest); err != nil {
		panic(err) // a fresh registry cannot already hold the queue
	}
	s.frames, _ = queue.AcquireSender[[]byte](s.queues, stateQueue)
	s.mgr = mgr
	return s
}

// consolePrefix is the path everything the console serves lives under, so a
// reverse proxy can mount it next to other applications by prefix. The root
// redirects there.
const consolePrefix = "/pf"

func (s *consoleServer) handler() http.Handler {
	static, _ := fs.Sub(consoleFiles, "console")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, consolePrefix+"/", http.StatusFound)
	})
	mux.Handle("GET "+consolePrefix+"/", http.StripPrefix(consolePrefix+"/", http.FileServerFS(static)))
	mux.HandleFunc("GET "+consolePrefix+"/api/session", s.handleSession)
	mux.HandleFunc("POST "+consolePrefix+"/api/login", s.requireCSRF(s.handleLogin))
	mux.HandleFunc("POST "+consolePrefix+"/api/logout", s.requireCSRF(s.handleLogout))
	mux.HandleFunc("GET "+consolePrefix+"/api/state", s.requireAuth(s.handleState))
	mux.HandleFunc("GET "+consolePrefix+"/api/ws", s.requireAuth(s.handleWebSocket))
	mux.HandleFunc("POST "+consolePrefix+"/api/listeners", s.requireCSRF(s.requireAuth(s.handleAddListener)))
	mux.HandleFunc("POST "+consolePrefix+"/api/listeners/{id}/{action}", s.requireCSRF(s.requireAuth(s.handleListenerAction)))
	mux.HandleFunc("POST "+consolePrefix+"/api/pipes/{id}/stop", s.requireCSRF(s.requireAuth(s.handleStop)))
	s.apiRoutes(mux)
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
		// frame-ancestors 'self': the API tab shows Swagger UI in a frame.
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireCSRF accepts a request carrying the console's header or an API
// token: a cross-site form cannot set either. requireAuth checks the token.
func (s *consoleServer) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != "1" && r.Header.Get(apiTokenHeader) == "" {
			http.Error(w, "missing "+csrfHeader+" or "+apiTokenHeader+" header", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *consoleServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			if r.Header.Get(apiTokenHeader) != "" {
				time.Sleep(time.Second) // a wrong token: slow down guessing, as for login
			}
			writeError(w, http.StatusUnauthorized, "unauthorized: sign in, or send the console password in "+apiTokenHeader)
			return
		}
		next(w, r)
	}
}

func (s *consoleServer) authorized(r *http.Request) bool {
	return s.password == "" || s.tokenOK(r) || s.session(r) != nil
}

// tokenOK reports whether the request carries the console password in
// X-API-Token.
func (s *consoleServer) tokenOK(r *http.Request) bool {
	token := r.Header.Get(apiTokenHeader)
	return token != "" && s.passwordMatches(token)
}

// passwordMatches compares hashes so the time taken does not depend on length.
func (s *consoleServer) passwordMatches(candidate string) bool {
	got, want := sha256.Sum256([]byte(candidate)), sha256.Sum256([]byte(s.password))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// session also rechecks authorization after a WebSocket's HTTP middleware,
// so a logout racing the upgrade cannot leave an untracked socket open.
func (s *consoleServer) session(r *http.Request) *consoleSession {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[cookie.Value]
	if session != nil && !time.Now().Before(session.expires) {
		s.revokeLocked(cookie.Value)
		return nil
	}
	return session
}

func (s *consoleServer) revokeLocked(token string) {
	if session := s.sessions[token]; session != nil {
		close(session.revoked)
		delete(s.sessions, token)
	}
}

func (s *consoleServer) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"passwordRequired": s.password != "",
		"authorized":       s.authorized(r),
		"version":          version,
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
		if !s.passwordMatches(body.Password) {
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
	for t, session := range s.sessions {
		if !now.Before(session.expires) {
			s.revokeLocked(t)
		}
	}
	s.sessions[token] = &consoleSession{expires: now.Add(sessionLifetime), revoked: make(chan struct{})}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     consolePrefix,
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
		s.revokeLocked(cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: consolePrefix, MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

type consoleState struct {
	Version   string             `json:"version"`
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
		writeError(w, http.StatusBadRequest, "bad connection id")
		return
	}
	p := pipes.get(id)
	if p == nil {
		writeError(w, http.StatusNotFound, "no such connection")
		return
	}
	p.interrupt("reset from the console")
	log.Printf("console: reset pipe #%d %s -> %s", id, p.client.RemoteAddr(), p.listener.target)
	w.WriteHeader(http.StatusNoContent)
}

// broadcast is the stats emitter: every pushEvery it checks whether anything
// changed and, if so, publishes one frame to the state queue. No change, no
// event. Nothing is marshaled while no tab is subscribed.
func (s *consoleServer) broadcast(ctx context.Context) {
	defer s.queues.Shutdown(stateQueue) // wakes every subscriber with ErrClosed
	tick := time.NewTicker(s.pushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if !changes.take() || s.viewers.Load() == 0 {
			continue
		}
		if data, err := json.Marshal(s.state()); err == nil {
			_ = s.frames.Send(data) // never blocks: drop-oldest
		}
	}
}

// openSocket upgrades an authorized request to a WebSocket. quit is closed
// when the client leaves, its session is revoked or expires, or the console
// shuts down; the caller then stops writing and returns.
func (s *consoleServer) openSocket(w http.ResponseWriter, r *http.Request) (ws *wsConn, quit <-chan struct{}, ok bool) {
	// Recheck the session after the HTTP middleware, so a logout racing the
	// upgrade cannot leave an untracked socket open. A token never expires.
	var revoked <-chan struct{}
	var expiry <-chan time.Time
	var timer *time.Timer
	if s.password != "" && !s.tokenOK(r) {
		session := s.session(r)
		if session == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return nil, nil, false
		}
		revoked = session.revoked
		timer = time.NewTimer(time.Until(session.expires))
		expiry = timer.C
	}
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		if timer != nil {
			timer.Stop()
		}
		return nil, nil, false
	}
	// The client's side: answer pings, notice when it goes away.
	gone := make(chan struct{})
	go func() {
		_ = ws.readLoop()
		close(gone)
	}()
	q := make(chan struct{})
	go func() {
		defer close(q)
		if timer != nil {
			defer timer.Stop()
		}
		select {
		case <-s.ctx.Done():
			_ = ws.writeFrame(wsOpClose, []byte{0x03, 0xE9}) // 1001 going away
		case <-revoked:
			_ = ws.Close()
		case <-expiry:
			_ = ws.Close()
		case <-gone:
		}
	}()
	return ws, q, true
}

func (s *consoleServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, quit, ok := s.openSocket(w, r)
	if !ok {
		return
	}
	defer ws.Close()
	rx, err := queue.AcquireReceiver[[]byte](s.queues, stateQueue)
	if err != nil {
		return // shutting down
	}
	s.viewers.Add(1)
	defer s.viewers.Add(-1)
	defer rx.Close()
	done := make(chan struct{})
	defer close(done)

	// Recv cannot be cancelled, so a watcher closes the receiver when the
	// client leaves or the server stops; that wakes Recv with ErrClosed. It
	// also sends the pings.
	go func() {
		ping := time.NewTicker(wsPingInterval)
		defer ping.Stop()
		for {
			select {
			case <-quit:
			case <-done:
			case <-ping.C:
				if ws.writeFrame(wsOpPing, nil) == nil {
					continue
				}
			}
			rx.Close()
			return
		}
	}()

	// A new subscriber starts at the queue's tail, so send the current state
	// first; frames published from now on follow.
	data, err := json.Marshal(s.state())
	if err != nil || ws.writeFrame(wsOpText, data) != nil {
		return
	}
	for {
		frame, err := rx.Recv()
		if err != nil {
			return // closed by the watcher, the ping loop, or server shutdown
		}
		if ws.writeFrame(wsOpText, frame) != nil {
			return
		}
	}
}

func (s *consoleServer) state() consoleState {
	return consoleState{
		Version:   version,
		Host:      s.host,
		Now:       time.Now().UnixMilli(),
		Started:   s.started.UnixMilli(),
		Listeners: s.mgr.snapshot(),
		Manage:    s.mgr.info(),
	}
}

func (s *consoleServer) handleAddListener(w http.ResponseWriter, r *http.Request) {
	spec, ok := decodeSpec(w, r)
	if !ok {
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
		spec, ok := decodeSpec(w, r)
		if !ok {
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
