package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/wushilin/pf-simple/internal/tunnel"
)

// The relay hub: ad-hoc tunnels between two pf-client processes that meet
// here by a shared secret word.
//
//	pf-client serve   --- /serve   (control channel) ---+
//	                  --- /accept  (one per connection)-+-- hub
//	pf-client connect --- /connect (one per connection)-+
//
// The hub is multi-tenant. A tenant is a name and a serve token, which is
// its permission to register tunnels here; tenants are managed in the
// console and kept in the config file, which holds only the token's hash. A
// word names one tunnel and is what both sides type. The first tenant to
// register a word owns it for good: no other tenant may serve that word
// until an admin clears the binding in the console, or the tenant itself
// binds so many words that the one it served longest ago is released.
// Connecting needs only the word.
//
// "serve" registers its word and keeps a control channel open. Each
// "connect" opens one WebSocket per TCP connection; the hub gives the
// connection an id, asks the serving side over the control channel to bring
// a matching WebSocket to /accept, and then pipes the two like any other
// connection.
//
// Nothing caps how many tunnels or connections there are: only token
// holders can open tunnels, and each costs a WebSocket.
//
// Nothing is resumed. A WebSocket that breaks ends its connection, and a
// control channel that breaks ends the tunnel and every connection in it;
// the serving side registers again and the connecting side opens new
// connections. Only the bindings of words to tokens outlive a restart, and
// only when pf-simple runs from a config file, next to which they are kept.

const (
	// maxWordsPerToken bounds the words bound to one token. A serving side
	// that makes up a new word at every start leaves the old ones behind;
	// past this many, the one served longest ago is released.
	maxWordsPerToken = 256
	// A source address that is refused guessLimit times within guessWindow
	// is not answered again until the window has passed: words are short
	// enough to type, so guessing them must be slow.
	guessLimit     = 30
	guessWindow    = time.Minute
	maxTenants     = 10000
	maxTenantName  = 32
	newTokenLen    = 40
	relayOpenWait  = 10 * time.Second
	relayDenyDelay = time.Second
	// relayDenials bounds how many refusals may be in their delay at once,
	// and with that how fast secrets can be guessed.
	relayDenials = 16
)

type secretHash = [sha256.Size]byte

type tunnelHub struct {
	idle      time.Duration
	newID     func() int
	denyDelay time.Duration
	openWait  time.Duration
	denials   chan struct{}
	statePath string // where reservations are kept; "" keeps them in memory
	// persist writes the tenants to the config file; nil when pf-simple was
	// started from the command line, and tenants cannot be changed then.
	persist func([]tenantSpec) error

	guesses  guessLimiter
	maxWords int // maxWordsPerToken; tests lower it

	mu       sync.Mutex
	tenants  []*tenant // in the order they were added
	tunnels  map[secretHash]*relayTunnel
	reserved map[secretHash]*reservation
	nextRes  int
}

// tenant is one holder of a serve token.
type tenant struct {
	name string
	hash secretHash // of its serve token
}

// reservation binds a word to the tenant that first registered it, until an
// admin clears it.
type reservation struct {
	id         int
	Word       string `json:"word"`
	Name       string `json:"name"`       // what its serving side called the tunnel, last time
	Owner      string `json:"owner"`      // tenant name
	LastServed int64  `json:"lastServed"` // unix seconds: when it was registered or last dropped
}

// relayTunnel is one word being served.
type relayTunnel struct {
	key       secretHash
	word      string
	name      string         // given by the serving side; shown in the console
	owner     string         // tenant name
	stats     *listenerStats // counters, and the "listener" its pipes belong to
	started   time.Time
	ctl       *wsConn // the serving side's control channel
	serveAddr string

	mu      sync.Mutex
	why     string                // why the tunnel was closed, once it is
	pending map[string]*relayConn // asked of the serving side, not yet brought
	connIDs map[uint64]string     // open pipe -> connection id
	closed  bool
}

// relayConn is a connection waiting for the serving side's leg.
type relayConn struct {
	id     string
	leg    chan *tunnel.Stream
	failed chan string // why the serving side could not
}

// wordLabel is a word as logs and the flow log show it: the first group.
func wordLabel(word string) string { return word[:4] + "-…" }

// newTunnelHub takes tenants that loadConfig or parseArgs already checked,
// and loads the reservations kept in statePath, if any. One whose tenant no
// longer exists stays, unusable, until it is cleared.
func newTunnelHub(tenants []tenantSpec, idle time.Duration, newID func() int, statePath string) *tunnelHub {
	h := &tunnelHub{
		idle: idle, newID: newID,
		denyDelay: relayDenyDelay, openWait: relayOpenWait,
		denials:   make(chan struct{}, relayDenials),
		statePath: statePath,
		guesses:   guessLimiter{limit: guessLimit, seen: make(map[string]*guessCount)},
		maxWords:  maxWordsPerToken,
		tunnels:   make(map[secretHash]*relayTunnel),
		reserved:  make(map[secretHash]*reservation),
	}
	for _, spec := range tenants {
		raw, _ := hex.DecodeString(spec.TokenSHA256)
		h.tenants = append(h.tenants, &tenant{name: spec.Name, hash: secretHash(raw)})
	}
	if statePath == "" {
		return h
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("relay: cannot read reservations: %v", err)
		}
		return h
	}
	var saved []*reservation
	if err := json.Unmarshal(raw, &saved); err != nil {
		log.Printf("relay: ignoring unreadable reservations in %s: %v", statePath, err)
		return h
	}
	for _, res := range saved {
		if res == nil {
			continue
		}
		if res.Word, err = tunnel.NormalizeWord(res.Word); err != nil {
			continue // from before words had their present form
		}
		h.nextRes++
		res.id = h.nextRes
		h.reserved[sha256.Sum256([]byte(res.Word))] = res
	}
	return h
}

// ---------- tenants ----------

var (
	errTenantsFixed = errors.New("tenants can only be changed when pf-simple runs from a config file (-c); these came from --tunnel")
	errNoTenant     = errors.New("no such tenant")
	errTenantExists = errors.New("a tenant with this name already exists")
)

func checkTenantName(name string) error {
	if name == "" || len(name) > maxTenantName {
		return fmt.Errorf("a tenant name is 1 to %d characters long", maxTenantName)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return errors.New("a tenant name may only use letters, digits, '-', '_' and '.'")
		}
	}
	return nil
}

// checkTenants validates tenants from a config file.
func checkTenants(specs []tenantSpec) error {
	names, hashes := make(map[string]bool), make(map[string]bool)
	if len(specs) > maxTenants {
		return fmt.Errorf("at most %d tenants", maxTenants)
	}
	for i, spec := range specs {
		if err := checkTenantName(spec.Name); err != nil {
			return fmt.Errorf("tenant #%d: %w", i+1, err)
		}
		raw, err := hex.DecodeString(spec.TokenSHA256)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("tenant %s: token_sha256 must be the SHA-256 of its serve token, as 64 hex digits; add tenants in the console to have it generated", spec.Name)
		}
		hash := strings.ToLower(spec.TokenSHA256)
		if names[spec.Name] || hashes[hash] {
			return fmt.Errorf("tenant %s: names and tokens must be unique", spec.Name)
		}
		names[spec.Name], hashes[hash] = true, true
	}
	return nil
}

// tenantOfLocked returns the tenant holding this serve token.
func (h *tunnelHub) tenantOfLocked(token string) *tenant {
	given := sha256.Sum256([]byte(token))
	var found *tenant
	for _, t := range h.tenants { // every one, so timing does not name the match
		if subtle.ConstantTimeCompare(given[:], t.hash[:]) == 1 {
			found = t
		}
	}
	return found
}

func (h *tunnelHub) tenantLocked(name string) *tenant {
	for _, t := range h.tenants {
		if t.name == name {
			return t
		}
	}
	return nil
}

func tenantSpecs(tenants []*tenant) []tenantSpec {
	specs := make([]tenantSpec, len(tenants))
	for i, t := range tenants {
		specs[i] = tenantSpec{Name: t.name, TokenSHA256: hex.EncodeToString(t.hash[:])}
	}
	return specs
}

// newServeToken returns a random token of letters and digits.
func newServeToken() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	out := make([]byte, 0, newTokenLen)
	var b [1]byte
	for len(out) < newTokenLen {
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		if b[0] < 248 { // 248 = 4 * 62: no modulo bias
			out = append(out, alphabet[b[0]%62])
		}
	}
	return string(out), nil
}

// changeTenantsLocked replaces the tenant list: saved to the config file
// first, and only used once that worked.
func (h *tunnelHub) changeTenantsLocked(next []*tenant) error {
	if h.persist == nil {
		return errTenantsFixed
	}
	if err := h.persist(tenantSpecs(next)); err != nil {
		return err
	}
	h.tenants = next
	changes.notify()
	return nil
}

// addTenant creates a tenant and returns its serve token. The token is not
// kept, only its hash, so this is the one time it can be shown.
func (h *tunnelHub) addTenant(name string) (string, error) {
	if err := checkTenantName(name); err != nil {
		return "", err
	}
	token, err := newServeToken()
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tenantLocked(name) != nil {
		return "", errTenantExists
	}
	if len(h.tenants) >= maxTenants {
		return "", fmt.Errorf("this server already has its limit of %d tenants", maxTenants)
	}
	next := append(append([]*tenant{}, h.tenants...), &tenant{name: name, hash: sha256.Sum256([]byte(token))})
	if err := h.changeTenantsLocked(next); err != nil {
		return "", err
	}
	log.Printf("relay: added tenant %s", name)
	return token, nil
}

// rotateTenant gives a tenant a new serve token. The old one stops working
// and the tenant's tunnels end; its words stay bound to it.
func (h *tunnelHub) rotateTenant(name string) (string, error) {
	token, err := newServeToken()
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	old := h.tenantLocked(name)
	if old == nil {
		h.mu.Unlock()
		return "", errNoTenant
	}
	next := make([]*tenant, len(h.tenants))
	for i, t := range h.tenants {
		next[i] = t
		if t == old {
			next[i] = &tenant{name: name, hash: sha256.Sum256([]byte(token))}
		}
	}
	if err := h.changeTenantsLocked(next); err != nil {
		h.mu.Unlock()
		return "", err
	}
	live := h.tunnelsOfLocked(name)
	h.mu.Unlock()
	for _, t := range live {
		h.drop(t, "the tenant's serve token was replaced")
	}
	log.Printf("relay: tenant %s has a new serve token", name)
	return token, nil
}

// deleteTenant removes a tenant, its tunnels and the bindings of its words.
func (h *tunnelHub) deleteTenant(name string) error {
	h.mu.Lock()
	if h.tenantLocked(name) == nil {
		h.mu.Unlock()
		return errNoTenant
	}
	next := make([]*tenant, 0, len(h.tenants))
	for _, t := range h.tenants {
		if t.name != name {
			next = append(next, t)
		}
	}
	if err := h.changeTenantsLocked(next); err != nil {
		h.mu.Unlock()
		return err
	}
	live := h.tunnelsOfLocked(name)
	for key, res := range h.reserved {
		if res.Owner == name {
			delete(h.reserved, key)
		}
	}
	h.saveLocked()
	h.mu.Unlock()
	for _, t := range live {
		h.drop(t, "its tenant was deleted")
	}
	log.Printf("relay: deleted tenant %s", name)
	return nil
}

func (h *tunnelHub) tunnelsOfLocked(owner string) []*relayTunnel {
	var out []*relayTunnel
	for _, t := range h.tunnels {
		if t.owner == owner {
			out = append(out, t)
		}
	}
	return out
}

// saveLocked writes the reservations atomically, readable by the owner only:
// the words in it are secrets.
func (h *tunnelHub) saveLocked() {
	if h.statePath == "" {
		return
	}
	list := make([]*reservation, 0, len(h.reserved))
	for _, res := range h.reserved {
		list = append(list, res)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].id < list[j].id })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		var tmp *os.File
		if tmp, err = os.CreateTemp(filepath.Dir(h.statePath), ".pf-simple-relay-*.json"); err == nil {
			defer os.Remove(tmp.Name()) // no-op after a successful rename
			if err = tmp.Chmod(0o600); err == nil {
				_, err = tmp.Write(data)
			}
			if cerr := tmp.Close(); err == nil {
				err = cerr
			}
			if err == nil {
				err = os.Rename(tmp.Name(), h.statePath)
			}
		}
	}
	if err != nil {
		log.Printf("relay: cannot save reservations: %v", err)
	}
}

func (h *tunnelHub) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tunnel.Path+"/serve", h.guard(h.handleServe))
	mux.HandleFunc("GET "+tunnel.Path+"/check", h.guard(h.handleCheck))
	mux.HandleFunc("GET "+tunnel.Path+"/connect", h.guard(h.handleConnect))
	mux.HandleFunc("GET "+tunnel.Path+"/accept", h.guard(h.handleAccept))
}

// guessLimiter counts refusals per source address.
type guessLimiter struct {
	limit int
	mu    sync.Mutex
	seen  map[string]*guessCount
}

type guessCount struct {
	n     int
	since time.Time
}

// blocked reports whether key has used up its refusals for now.
func (g *guessLimiter) blocked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.seen[key]
	if c != nil && time.Since(c.since) >= guessWindow {
		delete(g.seen, key)
		c = nil
	}
	return c != nil && c.n >= g.limit
}

func (g *guessLimiter) failed(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.seen) >= 10000 { // many addresses at once: forget the finished ones
		for k, c := range g.seen {
			if time.Since(c.since) >= guessWindow {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= 10000 {
			clear(g.seen)
		}
	}
	c := g.seen[key]
	if c == nil || time.Since(c.since) >= guessWindow {
		c = &guessCount{since: time.Now()}
		g.seen[key] = c
	}
	c.n++
}

// sourceKey is the address refusals are counted against. Behind a reverse
// proxy on this host or this network that is the address the proxy reports;
// a client that reaches the hub directly cannot pick its own. IPv6 clients
// are counted by /64, which one client can roam within.
func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if fwd := r.Header.Values("X-Forwarded-For"); len(fwd) > 0 {
			parts := strings.Split(fwd[len(fwd)-1], ",")
			if client := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); client != nil {
				ip = client
			}
		}
	}
	if ip == nil {
		return host
	}
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return ip.String()
}

// guard refuses an address that has been refused too often, before looking
// at what it sent: once blocked, a right guess is not told apart from a
// wrong one.
func (h *tunnelHub) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.guesses.blocked(sourceKey(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(guessWindow/time.Second)))
			writeError(w, http.StatusTooManyRequests, "too many refused attempts from your address; try again in a minute")
			return
		}
		next(w, r)
	}
}

// deny refuses after a delay, as the console does for a wrong password, and
// counts the refusal against the sender's address.
func (h *tunnelHub) deny(w http.ResponseWriter, r *http.Request) {
	h.guesses.failed(sourceKey(r))
	select {
	case h.denials <- struct{}{}:
		time.Sleep(h.denyDelay)
		<-h.denials
		writeError(w, http.StatusForbidden, "access denied")
	default:
		writeError(w, http.StatusTooManyRequests, "too many refused attempts; try again shortly")
	}
}

// find returns the tunnel a request's word names. Tunnels are keyed by the
// word's hash, so the lookup's timing says nothing about the word.
func (h *tunnelHub) find(r *http.Request) *relayTunnel {
	word, err := tunnel.NormalizeWord(r.Header.Get(tunnel.HeaderWord))
	if err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tunnels[sha256.Sum256([]byte(word))]
}

// peerAddr is the address to show for a request's sender. The hub sits
// behind a TLS reverse proxy, so the socket's address is the proxy's; the
// last X-Forwarded-For entry is what that proxy saw. A client that reaches
// the hub directly can put anything there, so this is for display only.
func peerAddr(r *http.Request) string {
	fwd := r.Header.Values("X-Forwarded-For")
	if len(fwd) > 0 {
		parts := strings.Split(fwd[len(fwd)-1], ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String() + " via " + r.RemoteAddr
		}
	}
	return r.RemoteAddr
}

// tunnelName decodes and checks the name a serving side gives its tunnel.
func tunnelName(header string) (string, error) {
	name, err := url.QueryUnescape(header)
	name = strings.TrimSpace(name)
	switch {
	case err != nil || name == "":
		return "", errors.New("give the tunnel a name: pf-client serve --name \"Office SSH\" ...")
	case utf8.RuneCountInString(name) > maxNameLen:
		return "", fmt.Errorf("the tunnel name is longer than %d characters", maxNameLen)
	case !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl):
		return "", errors.New("the tunnel name may not contain control characters")
	}
	return name, nil
}

// cleanHeader keeps a client-supplied label short and printable.
func cleanHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, s)
	return s[:min(len(s), 128)]
}

// handleServe registers a word and holds its control channel until the
// serving side leaves. Serving a word that is already being served, as the
// tenant that owns it, takes it over and ends the old tunnel: that is how a
// serving side that lost its link gets back in before the hub has noticed.
func (h *tunnelHub) handleServe(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	holder := h.tenantOfLocked(r.Header.Get(tunnel.HeaderServe))
	h.mu.Unlock()
	if holder == nil {
		h.deny(w, r)
		return
	}
	owner := holder.name
	word, err := tunnel.NormalizeWord(r.Header.Get(tunnel.HeaderWord))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := tunnelName(r.Header.Get(tunnel.HeaderName))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := cleanHeader(r.Header.Get(tunnel.HeaderTarget))
	key := sha256.Sum256([]byte(word))

	h.mu.Lock()
	res := h.reserved[key]
	refusal, status := "", 0
	switch {
	case h.tenantLocked(owner) != holder: // deleted or rotated a moment ago
		refusal, status = "access denied", http.StatusForbidden
	case res != nil && res.Owner != owner:
		refusal, status = "this word belongs to another tenant; choose a different word", http.StatusConflict
	case res == nil && !h.makeRoomLocked(owner):
		refusal, status = "this token is already serving its limit of "+strconv.Itoa(h.maxWords)+" words", http.StatusServiceUnavailable
	}
	if refusal != "" {
		h.mu.Unlock()
		if status != http.StatusServiceUnavailable {
			// Naming a word that is someone else's is a guess at it too.
			h.guesses.failed(sourceKey(r))
		}
		writeError(w, status, refusal)
		return
	}
	if res == nil {
		h.nextRes++
		res = &reservation{id: h.nextRes, Word: word, Owner: owner}
		h.reserved[key] = res
	}
	res.LastServed, res.Name = time.Now().Unix(), name
	h.saveLocked()
	h.mu.Unlock()

	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	ws.SetTimeouts(tunnel.ControlSilence, tunnel.WriteTimeout)
	stats := newListenerStats(h.newID(), wordLabel(word), target)
	stats.name = name
	t := &relayTunnel{
		key: key, word: word, name: name, owner: owner, stats: stats, started: time.Now(),
		ctl: ws, serveAddr: peerAddr(r),
		pending: make(map[string]*relayConn), connIDs: make(map[uint64]string),
	}
	h.mu.Lock()
	if h.reserved[key] != res || h.tenantLocked(owner) != holder { // changed while the handshake was under way
		h.mu.Unlock()
		_ = ws.Close()
		return
	}
	old := h.tunnels[key]
	h.tunnels[key] = t
	h.mu.Unlock()
	if old != nil {
		h.drop(old, "served again from "+peerAddr(r))
	}
	changes.notify()
	log.Printf("relay: %s (%s) serves %q as %s -> %s", owner, peerAddr(r), name, wordLabel(word), target)

	_ = ws.ReadLoop() // until the serving side leaves or falls silent
	h.drop(t, "the serving side disconnected")
}

// makeRoomLocked makes sure owner may bind one more word, releasing the one
// it served longest ago if it is at its limit. It reports false when every
// word it has is being served right now.
func (h *tunnelHub) makeRoomLocked(owner string) bool {
	count := 0
	var oldestKey secretHash
	var oldest *reservation
	for key, res := range h.reserved {
		if res.Owner != owner {
			continue
		}
		count++
		if h.tunnels[key] == nil && (oldest == nil || res.LastServed < oldest.LastServed || (res.LastServed == oldest.LastServed && res.id < oldest.id)) {
			oldestKey, oldest = key, res
		}
	}
	if count < h.maxWords {
		return true
	}
	if oldest == nil {
		return false
	}
	delete(h.reserved, oldestKey)
	log.Printf("relay: released %s, the word %s served longest ago, to make room for a new one", wordLabel(oldest.Word), owner)
	return true
}

// drop ends a tunnel and resets its connections. Its word stays reserved.
func (h *tunnelHub) drop(t *relayTunnel, why string) {
	h.mu.Lock()
	if h.tunnels[t.key] == t {
		delete(h.tunnels, t.key)
		if res := h.reserved[t.key]; res != nil {
			res.LastServed = time.Now().Unix()
			h.saveLocked()
		}
	}
	h.mu.Unlock()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed, t.why = true, why
	waiting := t.pending
	t.pending = nil
	t.mu.Unlock()
	_ = t.ctl.WriteFrame(wsOpClose, []byte{0x03, 0xE9}) // 1001 going away
	_ = t.ctl.Close()
	for _, c := range waiting {
		c.fail("the tunnel closed")
	}
	pipes.interruptListener(t.stats)
	changes.notify()
	log.Printf("relay: closed %s: %s", wordLabel(t.word), why)
}

var errNoWord = errors.New("no such word")

// reset ends the tunnel of reservation id; its serving side registers again
// on its own, so this resets the tunnel's connections. With clear, the
// binding goes too and the word is free for whichever tenant registers it
// next.
func (h *tunnelHub) reset(id int, clear bool) error {
	h.mu.Lock()
	var t *relayTunnel
	found := false
	for key, res := range h.reserved {
		if res.id != id {
			continue
		}
		found, t = true, h.tunnels[key]
		if clear {
			delete(h.reserved, key)
			h.saveLocked()
			log.Printf("relay: the reservation of %s was cleared from the console", wordLabel(res.Word))
		}
	}
	h.mu.Unlock()
	if !found {
		return errNoWord
	}
	if t != nil {
		h.drop(t, "reset from the console")
	}
	changes.notify()
	return nil
}

func (h *tunnelHub) closeAll() {
	h.mu.Lock()
	all := make([]*relayTunnel, 0, len(h.tunnels))
	for _, t := range h.tunnels {
		all = append(all, t)
	}
	h.mu.Unlock()
	for _, t := range all {
		h.drop(t, "shutting down")
	}
}

func (h *tunnelHub) handleCheck(w http.ResponseWriter, r *http.Request) {
	if h.find(r) == nil {
		h.deny(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *relayConn) fail(reason string) {
	select {
	case c.failed <- reason:
	default:
	}
}

func newConnID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// open asks the serving side for its leg of connection id and waits for it.
// It returns the leg, or why there is none.
func (h *tunnelHub) open(t *relayTunnel, id string) (*tunnel.Stream, string) {
	c := &relayConn{id: id, leg: make(chan *tunnel.Stream, 1), failed: make(chan string, 1)}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, "the tunnel closed"
	}
	t.pending[c.id] = c
	t.mu.Unlock()

	// wait reports the serving side's answer: its leg or its reason. With
	// neither in time, answered is false.
	wait := func() (leg *tunnel.Stream, reason string, answered bool) {
		timer := time.NewTimer(h.openWait)
		defer timer.Stop()
		select {
		case leg := <-c.leg:
			return leg, "", true
		case reason := <-c.failed:
			return nil, reason, true
		case <-timer.C:
			return nil, "the serving side did not answer", false
		}
	}
	leg, reason, answered := (*tunnel.Stream)(nil), "the serving side is not connected", false
	msg, _ := json.Marshal(tunnel.ControlMessage{Open: c.id})
	if t.ctl.WriteFrame(wsOpText, msg) == nil {
		leg, reason, answered = wait()
	}
	if leg != nil {
		return leg, ""
	}
	// If /accept claimed the connection just as we gave up, its leg is on
	// the way; take it so it is closed rather than left open.
	t.mu.Lock()
	_, unclaimed := t.pending[c.id]
	delete(t.pending, c.id)
	t.mu.Unlock()
	if !answered && !unclaimed {
		if late, _, _ := wait(); late != nil {
			late.Fail(reason)
		}
	}
	return nil, reason
}

// handleConnect is the connecting side's leg of a new connection.
func (h *tunnelHub) handleConnect(w http.ResponseWriter, r *http.Request) {
	t := h.find(r)
	if t == nil {
		h.deny(w, r)
		return
	}
	connID, err := newConnID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ws, err := tunnel.Upgrade(w, r, http.Header{tunnel.HeaderConn: {connID}})
	if err != nil {
		return
	}
	client := tunnel.NewStream(ws)
	client.SetRemote(peerAddr(r))
	id, start, l := connIDs.Add(1), time.Now(), t.stats
	l.active.Add(1)
	defer l.release()
	l.accepted.Add(1)
	changes.notify()
	upstream, reason := h.open(t, connID)
	if upstream == nil {
		l.failed.Add(1)
		changes.notify()
		flows.refused(id, l, start, client, flowFailed, reason)
		client.Fail(reason)
		return
	}
	t.mu.Lock()
	t.connIDs[id] = connID
	t.mu.Unlock()
	// When the hub cuts a leg, it says what broke, so that side's log can
	// name the hop and not just "closed".
	client.CloseReason = func() string {
		return relayCloseReason(id, t, client, upstream, "pf-client connect", "pf-client serve", "the application", "the target")
	}
	upstream.CloseReason = func() string {
		return relayCloseReason(id, t, upstream, client, "pf-client serve", "pf-client connect", "the target", "the application")
	}
	defer func() {
		t.mu.Lock()
		delete(t.connIDs, id)
		t.mu.Unlock()
	}()
	servePipe(id, start, client, upstream, l, h.idle)
}

// relayCloseReason is what the hub tells the pf-client on leg self when it
// cuts that leg: what happened on the other leg, or what the hub itself
// decided. selfLocal and otherLocal are what the two pf-clients connect to
// (the application, the target); selfClient and otherClient are the
// pf-clients on the two legs. Empty when self's link was lost and nobody is
// left to tell.
func relayCloseReason(pipeID uint64, t *relayTunnel, self, other *tunnel.Stream, selfClient, otherClient, selfLocal, otherLocal string) string {
	silentLink := func(client string) string {
		return "the link between " + client + " and the server was silent for " + halfCloseIdleTimeout.String()
	}
	if p := pipes.get(pipeID); p != nil && p.interrupted.Load() {
		if r := p.resetReason.Load(); r != nil && *r != "listener stopped" {
			return "the server reset the connection (" + *r + ")"
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		return "the tunnel was closed on the server: " + t.why
	}
	if err := other.Failure(); err != nil {
		var remote *tunnel.RemoteError
		var netErr net.Error
		switch {
		case errors.As(err, &remote):
			return remote.Reason
		case errors.As(err, &netErr) && netErr.Timeout():
			return silentLink(otherClient)
		}
		return "the link between " + otherClient + " and the server was lost"
	}
	if err := self.Failure(); err != nil {
		// The hub heard nothing from this leg; what it sends may still arrive.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return silentLink(selfClient)
		}
		return ""
	}
	idle := halfCloseIdleTimeout.String()
	switch {
	case other.HalfClosed():
		return otherLocal + " closed its end, and the connection was idle for " + idle
	case self.HalfClosed():
		return selfLocal + " closed its end, " + otherLocal + " kept its own open, and the connection was idle for " + idle
	}
	return "the server closed the connection"
}

// handleAccept is the serving side's leg of a connection the hub asked for,
// or word that the target could not be reached.
func (h *tunnelHub) handleAccept(w http.ResponseWriter, r *http.Request) {
	t := h.find(r)
	if t == nil {
		h.deny(w, r)
		return
	}
	id := r.Header.Get(tunnel.HeaderConn)
	t.mu.Lock()
	c := t.pending[id]
	delete(t.pending, id)
	t.mu.Unlock()
	if c == nil {
		writeError(w, http.StatusNotFound, "no such connection; it has ended")
		return
	}
	if reason := cleanHeader(r.Header.Get(tunnel.HeaderError)); reason != "" {
		c.fail(reason)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		c.fail("the serving side did not answer")
		return
	}
	leg := tunnel.NewStream(ws)
	leg.SetRemote(peerAddr(r))
	c.leg <- leg
}

// ---------- console view ----------

type relayState struct {
	// Manage says whether tenants can be added, rotated and deleted: only
	// when they are kept in a config file.
	Manage  bool                  `json:"manage"`
	Tenants []relayTenantSnapshot `json:"tenants"`
	Words   []relayWordSnapshot   `json:"words"`
}

type relayTenantSnapshot struct {
	Name  string `json:"name"`
	Words int    `json:"words"` // bound to it
	Live  int    `json:"live"`  // tunnels it serves now
}

// relayWordSnapshot is one reserved word, and its tunnel while it is served.
type relayWordSnapshot struct {
	ID         int    `json:"id"`
	Name       string `json:"name"` // given by the serving side
	Word       string `json:"word"`
	Owner      string `json:"owner"`      // the tenant it is bound to
	Orphan     bool   `json:"orphan"`     // that tenant no longer exists
	LastServed int64  `json:"lastServed"` // unix milliseconds
	Live       bool   `json:"live"`

	ServeAddr string `json:"serveAddr,omitempty"`
	Target    string `json:"target,omitempty"`
	Since     int64  `json:"since,omitempty"` // served since, unix milliseconds
	Accepted  uint64 `json:"accepted"`
	Failed    uint64 `json:"failed"`
	BytesUp   uint64 `json:"bytesUp"` // towards the serving side, closed + live
	BytesDown uint64 `json:"bytesDown"`
	// Conns counts every open connection; Sessions lists at most the newest
	// maxSnapshotPipes.
	Conns    int            `json:"conns"`
	Sessions []relaySession `json:"sessions"`
}

// relaySession is one open connection. In the embedded pipe, "client" is the
// connecting side and "upstream" the serving side.
type relaySession struct {
	pipeSnapshot
	ConnID string `json:"connId"`
}

func (h *tunnelHub) snapshot() relayState {
	h.mu.Lock()
	type entry struct {
		res reservation
		t   *relayTunnel
	}
	entries := make([]entry, 0, len(h.reserved))
	for key, res := range h.reserved {
		entries = append(entries, entry{*res, h.tunnels[key]})
	}
	tenants := make([]relayTenantSnapshot, len(h.tenants))
	index := make(map[string]*relayTenantSnapshot, len(h.tenants))
	for i, t := range h.tenants {
		tenants[i] = relayTenantSnapshot{Name: t.name}
		index[t.name] = &tenants[i]
	}
	for _, e := range entries {
		if ts := index[e.res.Owner]; ts != nil {
			ts.Words++
			if e.t != nil {
				ts.Live++
			}
		}
	}
	h.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].res.id < entries[j].res.id })

	var stats []*listenerStats
	for _, e := range entries {
		if e.t != nil {
			stats = append(stats, e.t.stats)
		}
	}
	live := pipes.snapshot(stats)
	out := relayState{Manage: h.persist != nil, Tenants: tenants, Words: make([]relayWordSnapshot, len(entries))}
	next := 0
	for i, e := range entries {
		ws := relayWordSnapshot{
			ID: e.res.id, Name: e.res.Name, Word: e.res.Word, Owner: e.res.Owner, Orphan: index[e.res.Owner] == nil,
			LastServed: e.res.LastServed * 1000, Sessions: []relaySession{},
		}
		if t := e.t; t != nil {
			ls := live[next]
			next++
			ws.Live = true
			ws.ServeAddr, ws.Target, ws.Since = t.serveAddr, ls.Target, t.started.UnixMilli()
			ws.Accepted, ws.Failed, ws.BytesUp, ws.BytesDown, ws.Conns = ls.Accepted, ls.Failed, ls.BytesUp, ls.BytesDown, ls.PipeCount
			t.mu.Lock()
			for _, p := range ls.Pipes {
				ws.Sessions = append(ws.Sessions, relaySession{p, t.connIDs[p.ID]})
			}
			t.mu.Unlock()
		}
		out.Words[i] = ws
	}
	return out
}

func (s *consoleServer) handleRelay(w http.ResponseWriter, r *http.Request) {
	if s.tunnels == nil {
		writeError(w, http.StatusNotFound, "the relay hub is off; start pf-simple with --tunnel or a [tunnel] table")
		return
	}
	writeJSON(w, s.tunnels.snapshot())
}

func (s *consoleServer) handleRelayAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	action := r.PathValue("action")
	if err != nil || (action != "reset" && action != "clear") {
		writeError(w, http.StatusBadRequest, "use /relay/{id}/reset or /relay/{id}/clear")
		return
	}
	if s.tunnels == nil || s.tunnels.reset(id, action == "clear") != nil {
		writeError(w, http.StatusNotFound, "no such word")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAddTenant creates a tenant; the response is the only place its
// serve token ever appears.
func (s *consoleServer) handleAddTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if s.tunnels == nil {
		writeError(w, http.StatusNotFound, "the relay hub is off")
		return
	}
	name := strings.TrimSpace(body.Name)
	token, err := s.tunnels.addTenant(name)
	answerTenant(w, name, token, err)
}

func (s *consoleServer) handleTenantAction(w http.ResponseWriter, r *http.Request) {
	if s.tunnels == nil {
		writeError(w, http.StatusNotFound, "the relay hub is off")
		return
	}
	name := r.PathValue("name")
	switch r.PathValue("action") {
	case "rotate":
		token, err := s.tunnels.rotateTenant(name)
		answerTenant(w, name, token, err)
	case "delete":
		answerTenant(w, name, "", s.tunnels.deleteTenant(name))
	default:
		writeError(w, http.StatusBadRequest, "use /relay/tenants/{name}/rotate or /delete")
	}
}

func answerTenant(w http.ResponseWriter, name, token string, err error) {
	switch {
	case err == nil && token == "":
		w.WriteHeader(http.StatusNoContent)
	case err == nil:
		writeJSON(w, map[string]string{"name": name, "token": token})
	case errors.Is(err, errNoTenant):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errTenantExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errTenantsFixed):
		writeError(w, http.StatusForbidden, err.Error())
	case strings.HasPrefix(err.Error(), "save listeners"):
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
