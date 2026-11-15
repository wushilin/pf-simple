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
	"sync/atomic"
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
	// persistSettings writes enabled and anonymous to the config file; nil
	// from the command line, and the switches are fixed then.
	persistSettings func(enabled, anonymous bool) error
	// persistReuse writes the limits on reusing legs; nil from the command
	// line, and they are fixed then.
	persistReuse func(reuseSettings) error

	// silent makes the hub answer like a server from before 0.14.0, which
	// announced no tunnel protocol. Tests only.
	silent bool
	// maxProto, when set, makes the hub speak no protocol newer than it,
	// like an older hub: 1 answers as pf-simple 0.14 does. Tests only.
	maxProto int

	guesses  guessLimiter
	maxWords int // maxWordsPerToken; tests lower it

	slots idleSlots // idle legs per tenant and in all (relay_reuse.go)

	quic *quicHub // the QUIC listener, protocol 3 (hub_quic.go); nil in some tests

	mu sync.Mutex
	// enabled is the hub's switch: off, its endpoints answer 404 as if it
	// were not there. anonymous lets "pf-client serve" register without a
	// serve token, as the built-in tenant anonymousOwner.
	enabled   bool
	anonymous bool
	reuse     reuseSettings // reusing accept legs, protocol 2
	tenants   []*tenant     // in the order they were added
	tunnels   map[secretHash]*relayTunnel
	reserved  map[secretHash]*reservation
	nextRes   int
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
	// Reuse overrides the hub's per-tunnel limits on idle legs for this word.
	Reuse *wordReuse `json:"reuse,omitempty"`
}

// relayTunnel is one word being served.
type relayTunnel struct {
	key   secretHash
	word  string
	name  string // given by the serving side; shown in the console
	owner string // tenant name
	// clientHash is the SHA-256 of the client token the serving side asks
	// of whoever connects; nil when it asks for none.
	clientHash *secretHash
	// peer is the serving side's program and version, and proto the tunnel
	// protocol chosen with it; for the log and the console.
	peer      string
	proto     int
	stats     *listenerStats // counters, and the "listener" its pipes belong to
	started   time.Time
	ctl       *wsConn    // the serving side's control channel, over WebSocket
	qs        *quicServe // or its registration over QUIC (hub_quic.go)
	serveAddr string
	// session is the registration's secret (protocol 2), which an accept
	// must bring back to be offered reuse; nil before protocol 2.
	session []byte
	done    chan struct{} // closed by drop
	reused  atomic.Uint64 // connections carried on a reused leg

	mu      sync.Mutex
	why     string                // why the tunnel was closed, once it is
	pending map[string]*relayConn // asked of the serving side, not yet brought
	connIDs map[uint64]string     // open pipe -> connection id
	legOf   map[uint64]*relayLeg  // open pipe -> its reusable leg, if it has one
	pool    []*idleLeg            // idle legs, oldest first
	nextLeg int
	closed  bool
}

// relayConn is a connection waiting for the serving side's leg.
type relayConn struct {
	id     string
	leg    chan servedLeg
	failed chan string // why the serving side could not
}

// servedLeg is a serving side's leg of a connection, and the reusable leg
// it runs on when it was offered reuse.
type servedLeg struct {
	s   *tunnel.Stream
	leg *relayLeg
}

var errNoLeg = errors.New("no such idle leg")

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
		enabled:   true,
		reuse:     defaultReuse,
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
	errTenantsFixed  = errors.New("tenants can only be changed when pf-simple runs from a config file (-c); these came from --tunnel")
	errNoTenant      = errors.New("no such tenant")
	errTenantExists  = errors.New("a tenant with this name already exists")
	errSettingsFixed = errors.New("the relay hub's settings can only be changed when pf-simple runs from a config file (-c)")
)

// anonymousOwner is the tenant that words served without a serve token
// belong to. No token can have this name.
const anonymousOwner = "anonymous"

func checkTenantName(name string) error {
	if strings.EqualFold(name, anonymousOwner) {
		return fmt.Errorf("the name %q is taken by serving without a token", anonymousOwner)
	}
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
	mux.HandleFunc("GET "+tunnel.Path+"/version", h.guard(h.handleVersion))
	mux.HandleFunc("GET "+tunnel.Path+"/quic", h.guard(h.handleQUICDiscovery))
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
		h.mu.Lock()
		on, silent, maxProto := h.enabled, h.silent, h.maxProto
		h.mu.Unlock()
		if !on { // as on a server without a hub
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !overTLS(r) {
			writeError(w, http.StatusBadRequest, "tunnels are only served over https: the word and the tokens must not travel in the clear")
			return
		}
		// Every answer from here on, refusals included, says which tunnel
		// protocol this server chose, and with that that it knows of them.
		min, max, err := tunnel.ParseProtoRange(r.Header.Get(tunnel.HeaderProto))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		proto, ok := tunnel.Negotiate(min, max)
		if maxProto > 0 && proto > maxProto {
			proto, ok = maxProto, maxProto >= min
		}
		if silent {
			next(w, r)
			return
		}
		if !ok {
			top := tunnel.ProtoMax
			if maxProto > 0 {
				top = maxProto
			}
			w.Header().Set(tunnel.HeaderProto, strconv.Itoa(top))
			writeError(w, http.StatusUpgradeRequired, tunnel.ProtoMismatch(min, max))
			return
		}
		w.Header().Set(tunnel.HeaderProto, strconv.Itoa(proto))
		if h.guesses.blocked(sourceKey(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(guessWindow/time.Second)))
			writeError(w, http.StatusTooManyRequests, "too many refused attempts from your address; try again in a minute")
			return
		}
		next(w, r)
	}
}

// overTLS reports whether a request reached the hub over https: on a TLS
// listener of its own, or through a reverse proxy that says so. pf-client
// refuses http:// URLs itself, which is what keeps its secrets off the
// wire; this turns away anything else that would send them in the clear,
// and a proxy that forwards from a plain listener.
func overTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
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

// peerVersion is the program and version a pf-client says it is. One from
// before it said so is older than 0.14.0.
func peerVersion(r *http.Request) string {
	v := cleanHeader(r.Header.Get(tunnel.HeaderVersion))
	if len(v) > 40 {
		v = v[:40]
	}
	if v == "" {
		return "pf-client before 0.14.0"
	}
	return v
}

// chosenProto is the tunnel protocol guard picked for this request.
func chosenProto(w http.ResponseWriter) int {
	n, _ := strconv.Atoi(w.Header().Get(tunnel.HeaderProto))
	return n
}

// admit returns the tunnel a connecting side may use: the one its word
// names, if it also brought the client token that tunnel asks for. A wrong
// or missing token is not told apart from a wrong word.
func (h *tunnelHub) admit(r *http.Request) *relayTunnel {
	t := h.find(r)
	given := sha256.Sum256([]byte(r.Header.Get(tunnel.HeaderClientToken)))
	if t == nil || (t.clientHash != nil && subtle.ConstantTimeCompare(given[:], t.clientHash[:]) != 1) {
		return nil
	}
	return t
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

// handleVersion tells a holder of a serve token which pf-simple this is and
// which tunnel protocols it speaks. Nobody else is told: a wrong or missing
// token is refused like any other wrong guess, also where serving needs no
// token.
func (h *tunnelHub) handleVersion(w http.ResponseWriter, r *http.Request) {
	var holder *tenant
	if token := r.Header.Get(tunnel.HeaderServe); token != "" {
		h.mu.Lock()
		holder = h.tenantOfLocked(token)
		h.mu.Unlock()
	}
	if holder == nil {
		h.deny(w, r)
		return
	}
	h.mu.Lock()
	protoMax := tunnel.ProtoMax
	if h.maxProto > 0 {
		protoMax = h.maxProto
	}
	h.mu.Unlock()
	writeJSON(w, tunnel.ServerInfo{Version: version, ProtoMin: tunnel.ProtoMin, ProtoMax: protoMax, Token: holder.name})
}

// handleServe registers a word and holds its control channel until the
// serving side leaves. Serving a word that is already being served, as the
// tenant that owns it, takes it over and ends the old tunnel: that is how a
// serving side that lost its link gets back in before the hub has noticed.
// serveReg is a registration that passed its checks, before it is
// installed.
type serveReg struct {
	owner, word, name, target string
	anon                      bool
	holder                    *tenant
	clientHash                *secretHash
	key                       secretHash
	res                       *reservation
}

// allowedLocked reports, under h.mu, whether the registration's owner may
// still serve.
func (sr *serveReg) allowedLocked(h *tunnelHub) bool {
	if sr.anon {
		return h.anonymous
	}
	return h.tenantLocked(sr.owner) == sr.holder
}

func (h *tunnelHub) handleServe(w http.ResponseWriter, r *http.Request) {
	sr := h.checkServe(w, r)
	if sr == nil {
		return
	}
	// Protocol 2: the registration's secret goes out with the 101 only,
	// never with a refusal (§12.3).
	var session []byte
	if chosenProto(w) >= 2 && isUpgrade(r) {
		if session = newSession(); session != nil {
			w.Header().Set(tunnel.HeaderSession, hex.EncodeToString(session))
		}
	}
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	ws.SetTimeouts(tunnel.ControlSilence, tunnel.WriteTimeout)
	t := h.newRelayTunnel(sr, r, chosenProto(w))
	t.ctl, t.session = ws, session
	if !h.install(t, sr, r) {
		_ = ws.Close()
		return
	}
	_ = ws.ReadLoop() // until the serving side leaves or falls silent
	h.drop(t, "the serving side disconnected")
}

// newRelayTunnel makes the tunnel of a registration, before its serving
// side's link is set.
func (h *tunnelHub) newRelayTunnel(sr *serveReg, r *http.Request, proto int) *relayTunnel {
	stats := newListenerStats(h.newID(), wordLabel(sr.word), sr.target)
	stats.name = sr.name
	return &relayTunnel{
		key: sr.key, word: sr.word, name: sr.name, owner: sr.owner, clientHash: sr.clientHash, stats: stats, started: time.Now(),
		peer: peerVersion(r), proto: proto, serveAddr: peerAddr(r), done: make(chan struct{}),
		pending: make(map[string]*relayConn), connIDs: make(map[uint64]string), legOf: make(map[uint64]*relayLeg),
	}
}

// install makes t the tunnel of its word, taking over from the one there,
// unless something changed while the serving side's link was being made.
func (h *tunnelHub) install(t *relayTunnel, sr *serveReg, r *http.Request) bool {
	h.mu.Lock()
	old := h.tunnels[sr.key]
	if h.reserved[sr.key] != sr.res || !h.enabled || !sr.allowedLocked(h) || (sr.anon && old != nil) {
		h.mu.Unlock()
		return false
	}
	h.tunnels[sr.key] = t
	h.mu.Unlock()
	if old != nil {
		h.drop(old, "served again from "+peerAddr(r))
	}
	changes.notify()
	log.Printf("relay: %s (%s, %s, tunnel protocol %d%s) serves %q as %s -> %s", sr.owner, peerAddr(r), t.peer, t.proto, t.transportNote(), sr.name, wordLabel(sr.word), sr.target)
	return true
}

// checkServe checks a registration. On a refusal it answers w and returns
// nil.
func (h *tunnelHub) checkServe(w http.ResponseWriter, r *http.Request) *serveReg {
	// Without a serve token the registration is anonymous, if the hub
	// allows that. A token that is given must be right either way.
	serveToken := r.Header.Get(tunnel.HeaderServe)
	h.mu.Lock()
	anon := serveToken == "" && h.anonymous
	var holder *tenant
	if serveToken != "" {
		holder = h.tenantOfLocked(serveToken)
	}
	h.mu.Unlock()
	if holder == nil && !anon {
		h.deny(w, r)
		return nil
	}
	owner := anonymousOwner
	if holder != nil {
		owner = holder.name
	}
	sr := &serveReg{owner: owner, anon: anon, holder: holder}
	var clientHash *secretHash
	if hexHash := r.Header.Get(tunnel.HeaderClientHash); hexHash != "" {
		raw, err := hex.DecodeString(hexHash)
		if err != nil || len(raw) != sha256.Size {
			writeError(w, http.StatusBadRequest, "the client token's hash must be 64 hex digits")
			return nil
		}
		sum := secretHash(raw)
		clientHash = &sum
	}
	word, err := tunnel.NormalizeWord(r.Header.Get(tunnel.HeaderWord))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil
	}
	name, err := tunnelName(r.Header.Get(tunnel.HeaderName))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil
	}
	target := cleanHeader(r.Header.Get(tunnel.HeaderTarget))
	key := sha256.Sum256([]byte(word))

	h.mu.Lock()
	res := h.reserved[key]
	refusal, status := "", 0
	switch {
	case !sr.allowedLocked(h): // deleted, rotated or switched off a moment ago
		refusal, status = "access denied", http.StatusForbidden
	case res != nil && res.Owner != owner:
		refusal, status = "this word belongs to another tenant; choose a different word", http.StatusConflict
	case anon && h.tunnels[key] != nil:
		// Anyone may serve anonymously, so nobody may take over a tunnel
		// that way. One whose serving side is gone frees its word as soon
		// as the hub notices, and the serving side keeps trying until then.
		refusal, status = "this word is being served already; without a serve token it cannot be taken over", http.StatusServiceUnavailable
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
		return nil
	}
	if res == nil {
		h.nextRes++
		res = &reservation{id: h.nextRes, Word: word, Owner: owner}
		h.reserved[key] = res
	}
	res.LastServed, res.Name = time.Now().Unix(), name
	h.saveLocked()
	h.mu.Unlock()
	sr.clientHash, sr.word, sr.name, sr.target, sr.key, sr.res = clientHash, word, name, target, key, res
	return sr
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
	close(t.done)
	t.mu.Unlock()
	h.closePool(t)
	if t.ctl != nil {
		// Bounded, also behind a write that is stuck: 1001, going away.
		t.ctl.BeginClose()
		_ = t.ctl.WriteFrame(wsOpClose, []byte{0x03, 0xE9})
		_ = t.ctl.Close()
	}
	if t.qs != nil {
		t.qs.end(why)
	}
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

// setSettings changes the hub's switches and saves them; nil leaves one as
// it is. Turning the hub off ends every tunnel. Turning anonymous serving
// off ends the tunnels served that way and frees their words.
func (h *tunnelHub) setSettings(enabled, anonymous *bool) error {
	h.mu.Lock()
	on, anon := h.enabled, h.anonymous
	if enabled != nil {
		on = *enabled
	}
	if anonymous != nil {
		anon = *anonymous
	}
	if on == h.enabled && anon == h.anonymous {
		h.mu.Unlock()
		return nil
	}
	if h.persistSettings == nil {
		h.mu.Unlock()
		return errSettingsFixed
	}
	if err := h.persistSettings(on, anon); err != nil {
		h.mu.Unlock()
		return err
	}
	wasOn, wasAnon := h.enabled, h.anonymous
	h.enabled, h.anonymous = on, anon
	var closing []*relayTunnel
	why := ""
	switch {
	case wasOn && !on:
		why = "the relay hub was turned off"
		for _, t := range h.tunnels {
			closing = append(closing, t)
		}
	case wasAnon && !anon:
		why = "serving without a token was turned off"
		closing = h.tunnelsOfLocked(anonymousOwner)
	}
	if wasAnon && !anon {
		for key, res := range h.reserved {
			if res.Owner == anonymousOwner {
				delete(h.reserved, key)
			}
		}
		h.saveLocked()
	}
	h.mu.Unlock()
	for _, t := range closing {
		h.drop(t, why)
	}
	log.Printf("relay: settings changed from the console: enabled=%v, anonymous serve=%v", on, anon)
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
	if h.quic != nil {
		h.quic.stop()
	}
}

func (h *tunnelHub) handleCheck(w http.ResponseWriter, r *http.Request) {
	if h.admit(r) == nil {
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

// open asks the serving side for its leg of connection id and waits for it:
// first on an idle leg of the tunnel's pool, if it has one (protocol 2),
// and otherwise with an open message. It returns the leg, or why there is
// none.
func (h *tunnelHub) open(t *relayTunnel, id string) (servedLeg, string) {
	if t.qs != nil {
		return h.openQUIC(t, id)
	}
	deadline := time.Now().Add(h.openWait)
	if s, leg := h.bind(t, id); s != nil {
		return servedLeg{s, leg}, ""
	}
	c := &relayConn{id: id, leg: make(chan servedLeg, 1), failed: make(chan string, 1)}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return servedLeg{}, "the tunnel closed"
	}
	t.pending[c.id] = c
	t.mu.Unlock()

	// wait reports the serving side's answer: its leg or its reason. With
	// neither in time, answered is false.
	wait := func(within time.Duration) (leg servedLeg, reason string, answered bool) {
		timer := time.NewTimer(max(within, time.Millisecond))
		defer timer.Stop()
		select {
		case leg := <-c.leg:
			return leg, "", true
		case reason := <-c.failed:
			return servedLeg{}, reason, true
		case <-timer.C:
			return servedLeg{}, "the serving side did not answer", false
		}
	}
	leg, reason, answered := servedLeg{}, "the serving side is not connected", false
	msg, _ := json.Marshal(tunnel.ControlMessage{Open: c.id})
	if t.ctl.WriteFrame(wsOpText, msg) == nil {
		leg, reason, answered = wait(time.Until(deadline))
	} else {
		// A serving side that stopped reading its control channel: fail
		// every write to it from now on, rather than let each connection
		// wait its turn for the write timeout, and end the tunnel.
		t.ctl.ExpireWrites()
		go h.drop(t, "the serving side stopped reading its control channel")
	}
	if leg.s != nil {
		return leg, ""
	}
	// If /accept claimed the connection just as we gave up, its leg is on
	// the way; take it so it is closed rather than left open.
	t.mu.Lock()
	_, unclaimed := t.pending[c.id]
	delete(t.pending, c.id)
	t.mu.Unlock()
	if !answered && !unclaimed {
		if late, _, _ := wait(h.openWait); late.s != nil {
			late.s.Fail(reason)
		}
	}
	return servedLeg{}, reason
}

// handleConnect is the connecting side's leg of a new connection.
func (h *tunnelHub) handleConnect(w http.ResponseWriter, r *http.Request) {
	t := h.admit(r)
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
	h.relay(t, connID, client)
}

// relay carries one connection, whose connecting side's leg is client,
// once it has its id: it asks the serving side for its leg and pipes the
// two.
func (h *tunnelHub) relay(t *relayTunnel, connID string, client *tunnel.Stream) {
	id, start, l := connIDs.Add(1), time.Now(), t.stats
	l.active.Add(1)
	defer l.release()
	l.accepted.Add(1)
	changes.notify()
	served, reason := h.open(t, connID)
	upstream := served.s
	if upstream == nil {
		l.failed.Add(1)
		changes.notify()
		flows.refused(id, l, start, client, flowFailed, reason)
		client.Fail(reason)
		return
	}
	t.mu.Lock()
	t.connIDs[id] = connID
	if served.leg != nil {
		t.legOf[id] = served.leg
	}
	t.mu.Unlock()
	// When the hub cuts a leg, it says what broke, so that side's log can
	// name the hop and not just "closed".
	client.CloseReason = func() string {
		return relayCloseReason(id, t, client, upstream, "pf-client connect", "pf-client serve", "the application", "the target")
	}
	upstream.CloseReason = func() string {
		return relayCloseReason(id, t, upstream, client, "pf-client serve", "pf-client connect", "the target", "the application")
	}
	// A failure of one leg after both half-closes on the other: that one
	// would otherwise finish cleanly and never hear it (§8.3).
	client.Failed = func() string { return remoteReason(upstream) }
	if served.leg == nil { // a reused leg ends its generation instead (§12.5)
		upstream.Failed = func() string { return remoteReason(client) }
	}
	defer func() {
		t.mu.Lock()
		delete(t.connIDs, id)
		delete(t.legOf, id)
		t.mu.Unlock()
	}()
	var up net.Conn = upstream
	if served.leg != nil {
		// Closing it offers the leg back for the next connection, after a
		// clean finish (protocol 2, §12.5).
		up = &reusableUpstream{Stream: upstream, h: h, t: t, leg: served.leg, client: client, pipeID: id}
	}
	servePipe(id, start, client, up, l, h.idle)
}

// remoteReason is the reason the far end of s gave for failing it, if it
// did.
func remoteReason(s *tunnel.Stream) string {
	var remote *tunnel.RemoteError
	if errors.As(s.Failure(), &remote) {
		return remote.Reason
	}
	return ""
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
	offered := h.offerReuse(w, r, t) // protocol 2: the offer goes out with the 101
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		c.fail("the serving side did not answer")
		return
	}
	leg := tunnel.NewStream(ws)
	leg.SetRemote(peerAddr(r))
	served := servedLeg{s: leg}
	if offered {
		leg.SetReusable(true)
		served.leg = t.newLeg(peerAddr(r))
	}
	c.leg <- served
}

// ---------- console view ----------

type relayState struct {
	// Manage says whether tenants can be added, rotated and deleted: only
	// when they are kept in a config file.
	Manage bool `json:"manage"`
	// Enabled and Anonymous are the hub's switches. With Enabled false the
	// rest is empty.
	Enabled   bool `json:"enabled"`
	Anonymous bool `json:"anonymous"`
	// Reuse is the hub's limits on reusing the serving side's legs
	// (protocol 2); ReuseFixed says they cannot be changed here.
	Reuse      reuseSettings         `json:"reuse"`
	ReuseFixed bool                  `json:"reuseFixed"`
	// QUIC is the QUIC listener (protocol 3): its settings and state.
	QUIC *quicStatus `json:"quic,omitempty"`
	Tenants    []relayTenantSnapshot `json:"tenants"`
	Words      []relayWordSnapshot   `json:"words"`
}

type relayTenantSnapshot struct {
	Name  string `json:"name"`
	Words int    `json:"words"` // bound to it
	Live  int    `json:"live"`  // tunnels it serves now
	// Anonymous marks the built-in tenant of serving without a token,
	// listed last while that is allowed. It cannot be rotated or deleted.
	Anonymous bool `json:"anonymous,omitempty"`
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

	// ClientToken: whoever connects must also give the serving side's
	// client token.
	ClientToken bool `json:"clientToken,omitempty"`
	// Transport is how the serving side reached the hub: "ws" or "quic".
	Transport string `json:"transport,omitempty"`
	// Client is the serving side's program and version, and Proto the
	// tunnel protocol in use with it.
	Client    string `json:"client,omitempty"`
	Proto     int    `json:"proto,omitempty"`
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

	// Reusing accept legs (protocol 2): Reuse says the serving side's legs
	// are reused; Reused counts the connections that ran on a reused leg;
	// Idle lists the idle legs, with the tunnel's limits on them.
	Reuse   bool           `json:"reuse,omitempty"`
	Reused  uint64         `json:"reused,omitempty"`
	MinIdle int            `json:"minIdle"`
	MaxIdle int            `json:"maxIdle"`
	IdleSec int            `json:"idleSeconds"`
	Idle    []idleSnapshot `json:"idle,omitempty"`
	// WordReuse is this word's own limits, where the console set them.
	WordReuse *wordReuse `json:"wordReuse,omitempty"`
}

// relaySession is one open connection. In the embedded pipe, "client" is the
// connecting side and "upstream" the serving side.
type relaySession struct {
	pipeSnapshot
	ConnID string `json:"connId"`
	// Leg and Carried: the reusable leg it runs on, and how many
	// connections that leg has carried, this one included (protocol 2).
	Leg     int `json:"leg,omitempty"`
	Carried int `json:"carried,omitempty"`
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
	tenants := make([]relayTenantSnapshot, len(h.tenants), len(h.tenants)+1)
	index := make(map[string]*relayTenantSnapshot, len(h.tenants)+1)
	for i, t := range h.tenants {
		tenants[i] = relayTenantSnapshot{Name: t.name}
	}
	if h.anonymous {
		tenants = append(tenants, relayTenantSnapshot{Name: anonymousOwner, Anonymous: true})
	}
	for i := range tenants {
		index[tenants[i].Name] = &tenants[i]
	}
	enabled, anonymous, reuse, reuseFixed := h.enabled, h.anonymous, h.reuse, h.persistReuse == nil
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
	out := relayState{Manage: h.persist != nil, Enabled: enabled, Anonymous: anonymous, Reuse: reuse, ReuseFixed: reuseFixed, Tenants: tenants, Words: make([]relayWordSnapshot, len(entries))}
	if h.quic != nil {
		out.QUIC = h.quic.status()
	}
	next := 0
	for i, e := range entries {
		ws := relayWordSnapshot{
			ID: e.res.id, Name: e.res.Name, Word: e.res.Word, Owner: e.res.Owner, Orphan: index[e.res.Owner] == nil,
			LastServed: e.res.LastServed * 1000, Sessions: []relaySession{}, WordReuse: e.res.Reuse,
		}
		if t := e.t; t != nil {
			ls := live[next]
			next++
			ws.Live, ws.ClientToken, ws.Transport = true, t.clientHash != nil, t.transport()
			ws.Client, ws.Proto = t.peer, t.proto
			ws.ServeAddr, ws.Target, ws.Since = t.serveAddr, ls.Target, t.started.UnixMilli()
			ws.Accepted, ws.Failed, ws.BytesUp, ws.BytesDown, ws.Conns = ls.Accepted, ls.Failed, ls.BytesUp, ls.BytesDown, ls.PipeCount
			rs := h.reuseFor(t)
			ws.Reuse = t.session != nil && rs.Enabled && rs.MaxIdle > 0
			ws.Reused, ws.MinIdle, ws.MaxIdle, ws.IdleSec = t.reused.Load(), rs.MinIdle, rs.MaxIdle, rs.IdleSec
			t.mu.Lock()
			for _, p := range ls.Pipes {
				rsn := relaySession{pipeSnapshot: p, ConnID: t.connIDs[p.ID]}
				if leg := t.legOf[p.ID]; leg != nil {
					rsn.Leg, rsn.Carried = leg.id, leg.carried
				}
				ws.Sessions = append(ws.Sessions, rsn)
			}
			limit := time.Duration(rs.IdleSec) * time.Second
			for i, il := range t.pool {
				is := idleSnapshot{
					Leg: il.leg.id, ServeAddr: il.leg.addr, Since: il.since.UnixMilli(), Carried: il.leg.carried,
					Kept: keptLocked(t, rs, i),
				}
				if !is.Kept {
					is.ClosesAt = il.since.Add(limit).UnixMilli()
				}
				ws.Idle = append(ws.Idle, is)
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

// handleRelaySettings changes the hub's switches; a field left out stays.
func (s *consoleServer) handleRelaySettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled   *bool           `json:"enabled"`
		Anonymous *bool           `json:"anonymous"`
		Reuse     json.RawMessage `json:"reuse"`
		QUIC      json.RawMessage `json:"quic"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body")
		return
	}
	// reuse, if given, must be whole and usable before anything changes: a
	// field left out would otherwise read as 0.
	var reuse *reuseSettings
	if len(body.Reuse) > 0 && string(body.Reuse) != "null" {
		var fields map[string]json.RawMessage
		var rs reuseSettings
		if json.Unmarshal(body.Reuse, &fields) != nil || json.Unmarshal(body.Reuse, &rs) != nil {
			writeError(w, http.StatusBadRequest, "reuse: bad value")
			return
		}
		for _, k := range []string{"enabled", "idleSeconds", "minIdle", "maxIdle", "tenantCap", "hubCap"} {
			if _, ok := fields[k]; !ok {
				writeError(w, http.StatusBadRequest, "reuse: "+k+" is missing; send all six fields")
				return
			}
		}
		if msg := rs.check(); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		reuse = &rs
	}
	// quic, too, is whole or nothing.
	var quic *quicSettings
	if len(body.QUIC) > 0 && string(body.QUIC) != "null" {
		var fields map[string]json.RawMessage
		var qs quicSettings
		if json.Unmarshal(body.QUIC, &fields) != nil || json.Unmarshal(body.QUIC, &qs) != nil {
			writeError(w, http.StatusBadRequest, "quic: bad value")
			return
		}
		for _, k := range []string{"enabled", "listen", "advertiseHost", "advertisePort", "maxConnections", "maxBufferedMiB"} {
			if _, ok := fields[k]; !ok {
				writeError(w, http.StatusBadRequest, "quic: "+k+" is missing; send all six fields")
				return
			}
		}
		if msg := qs.check(); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		quic = &qs
	}
	if s.tunnels == nil {
		writeError(w, http.StatusNotFound, "this server has no relay hub")
		return
	}
	err := s.tunnels.setSettings(body.Enabled, body.Anonymous)
	if err == nil && reuse != nil {
		err = s.tunnels.setReuse(*reuse)
	}
	if err == nil && quic != nil {
		if s.tunnels.quic == nil || s.tunnels.quic.persist == nil {
			err = errSettingsFixed
		} else {
			err = s.tunnels.quic.apply(*quic)
		}
	}
	var bad *badSetting
	if errors.As(err, &bad) {
		writeError(w, http.StatusBadRequest, bad.msg)
		return
	}
	switch {
	case err == nil:
		writeJSON(w, s.tunnels.snapshot())
	case errors.Is(err, errSettingsFixed):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
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
