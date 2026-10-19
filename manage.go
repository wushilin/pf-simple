package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// ---------- policy ----------

// managePolicy fences what the console may create. Each list is optional;
// an omitted one means no restriction.
type managePolicy struct {
	targetHosts *hostMatcher
	targetPorts *portMatcher
	bindHosts   *hostMatcher
	bindPorts   *portMatcher
}

// hostMatcher matches an IP against IPs and CIDRs, or a hostname exactly.
type hostMatcher struct {
	any   bool
	nets  []*net.IPNet
	names map[string]bool
	text  string
}

type portMatcher struct {
	ranges []portRange
	text   string
}

type portRange struct{ lo, hi int }

func newManagePolicy(c *consoleTable) (*managePolicy, error) {
	p := &managePolicy{}
	var err error
	if p.targetHosts, err = parseHostMatcher("allow_target_hosts", c.AllowTargetHosts); err != nil {
		return nil, err
	}
	if p.bindHosts, err = parseHostMatcher("allow_bind_hosts", c.AllowBindHosts); err != nil {
		return nil, err
	}
	if p.targetPorts, err = parsePortMatcher("allow_target_ports", c.AllowTargetPorts); err != nil {
		return nil, err
	}
	if p.bindPorts, err = parsePortMatcher("allow_bind_ports", c.AllowBindPorts); err != nil {
		return nil, err
	}
	return p, nil
}

// parseHostMatcher returns nil for an empty list (no restriction).
func parseHostMatcher(key string, values []string) (*hostMatcher, error) {
	if len(values) == 0 {
		return nil, nil
	}
	m := &hostMatcher{names: make(map[string]bool), text: strings.Join(values, ", ")}
	for _, v := range values {
		v = strings.TrimSpace(v)
		switch {
		case v == "*":
			m.any = true
		case strings.Contains(v, "/"):
			_, n, err := net.ParseCIDR(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not a valid CIDR", key, v)
			}
			m.nets = append(m.nets, n)
		case net.ParseIP(v) != nil:
			ip := net.ParseIP(v)
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			m.nets = append(m.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		case v != "" && !strings.ContainsAny(v, " :[]"):
			m.names[strings.ToLower(v)] = true
		default:
			return nil, fmt.Errorf("%s: %q is not an IP, CIDR, hostname or *", key, v)
		}
	}
	return m, nil
}

// allows matches an IP against the IPs and CIDRs, or a hostname by name. A
// hostname is never resolved, because DNS could later point it elsewhere.
func (m *hostMatcher) allows(host string) bool {
	if m == nil || m.any {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range m.nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return m.names[strings.ToLower(host)]
}

// parsePortMatcher returns nil for an empty value (no restriction).
func parsePortMatcher(key, value string) (*portMatcher, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	m := &portMatcher{text: value}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			hi = lo
		}
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		b, errB := strconv.Atoi(strings.TrimSpace(hi))
		if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("%s: %q is not a port or range like 18000-19999", key, part)
		}
		m.ranges = append(m.ranges, portRange{a, b})
	}
	return m, nil
}

func (m *portMatcher) allows(port string) bool {
	if m == nil {
		return true
	}
	n, _ := strconv.Atoi(port)
	for _, r := range m.ranges {
		if n >= r.lo && n <= r.hi {
			return true
		}
	}
	return false
}

// check reports why a normalized forwarding is outside the policy.
func (p *managePolicy) check(fw forwarding) error {
	bindHost, bindPort, _ := net.SplitHostPort(fw.listen)
	targetHost, targetPort, _ := net.SplitHostPort(fw.target)
	// An empty bind host means every interface; it passes only if the list
	// allows the unspecified address.
	bindOK := p.bindHosts.allows(bindHost)
	if bindHost == "" {
		bindOK = p.bindHosts.allows("0.0.0.0") || p.bindHosts.allows("::")
	}
	if !bindOK {
		shown := bindHost
		if shown == "" {
			shown = "all interfaces"
		}
		return fmt.Errorf("listen host %s is not allowed; allow_bind_hosts: %s", shown, p.bindHosts.text)
	}
	if !p.bindPorts.allows(bindPort) {
		return fmt.Errorf("listen port %s is not allowed; allow_bind_ports: %s", bindPort, p.bindPorts.text)
	}
	if !p.targetHosts.allows(targetHost) {
		return fmt.Errorf("target host %s is not allowed; allow_target_hosts: %s", targetHost, p.targetHosts.text)
	}
	if !p.targetPorts.allows(targetPort) {
		return fmt.Errorf("target port %s is not allowed; allow_target_ports: %s", targetPort, p.targetPorts.text)
	}
	return nil
}

// ---------- manager ----------

const (
	sourceConfig = "config" // in the config file; editable from the console
	sourceCLI    = "cli"    // from the command line; start and stop only
	// sourceRedirect is the enable_http_to_https_redirect listener on port
	// 80: best effort, start and stop only, never saved.
	sourceRedirect = "redirect"
)

type managedListener struct {
	stats   *listenerStats
	source  string
	enabled bool // what the user wants; saved as enabled = false when off
	running bool
	lastErr string

	ln         net.Listener
	stopAccept context.CancelFunc
	acceptDone chan struct{}
}

// manager owns every listener. Its mutex is held for the whole of each
// change, so add, start, stop, delete and save never interleave; byte
// counters and pipes do not touch it.
type manager struct {
	idle   time.Duration
	policy *managePolicy
	// configPath, consoleRaw and redirectRaw are used to rewrite the config file.
	configPath  string
	consoleRaw  *consoleTable
	redirectRaw *bool

	mu     sync.Mutex
	ctx    context.Context
	list   []*managedListener
	nextID int
}

var (
	errNotFound   = errors.New("no such listener")
	errReadOnly   = errors.New("this listener comes from the command line; it can be stopped and started, but not edited or deleted")
	errNoManaging = errors.New("listeners can only be added, edited or deleted when pf-simple runs from a config file (-c)")
	errRunning    = errors.New("stop the listener first")
	errRedirect   = errors.New("the HTTP to HTTPS redirect has no settings; it can be stopped and started, or turned off with enable_http_to_https_redirect = false")
)

func newManager(forwards []forwarding, policy *managePolicy, idle time.Duration) *manager {
	m := &manager{idle: idle, policy: policy, ctx: context.Background()}
	for _, f := range forwards {
		source := sourceCLI
		if f.fromFile {
			source = sourceConfig
		}
		m.appendLocked(f.stats, source, !f.disabled)
	}
	return m
}

func (m *manager) appendLocked(stats *listenerStats, source string, enabled bool) *managedListener {
	stats.id = m.nextID
	m.nextID++
	ml := &managedListener{stats: stats, source: source, enabled: enabled}
	m.list = append(m.list, ml)
	return ml
}

func (m *manager) findLocked(id int) *managedListener {
	for _, ml := range m.list {
		if ml.stats.id == id {
			return ml
		}
	}
	return nil
}

func (m *manager) findListenLocked(listen string) *managedListener {
	for _, ml := range m.list {
		if ml.stats.listen == listen {
			return ml
		}
	}
	return nil
}

// startAll binds every enabled listener. Without listener management a bind
// failure is fatal, as before. With it, the listener records the error and
// stays stopped so the console can show it and the rest keep running.
func (m *manager) startAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = ctx
	for _, ml := range m.list {
		if !ml.enabled {
			continue
		}
		if err := m.startLocked(ml); err != nil {
			if m.policy == nil && ml.source != sourceRedirect {
				m.closeAllLocked()
				return fmt.Errorf("listen on %s: %w", ml.stats.listen, err)
			}
			log.Printf("could not start %s: %v", ml.stats.labelFor(ml.stats.listen), err)
		}
	}
	return nil
}

func (m *manager) startLocked(ml *managedListener) error {
	if ml.running {
		return nil
	}
	ln, err := net.Listen("tcp", ml.stats.listen)
	if err != nil {
		ml.lastErr = err.Error()
		changes.notify()
		return err
	}
	ml.stats.closing.Store(false)
	actx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	ml.ln, ml.stopAccept, ml.acceptDone = ln, cancel, done
	ml.running, ml.lastErr = true, ""
	if ml.source == sourceRedirect {
		go func() {
			defer close(done)
			serveHTTPRedirect(actx, ln, ml.stats)
		}()
		log.Printf("redirecting http://%s to https", ln.Addr())
		changes.notify()
		return nil
	}
	go func() {
		defer close(done)
		acceptConnections(actx, ln, ml.stats, m.idle)
	}()
	log.Printf("forwarding %s -> %s%s", ml.stats.labelFor(ml.stats.listen), ml.stats.target, ml.stats.limitsNote())
	changes.notify()
	return nil
}

// stopWait bounds how long a stop waits for reset pipes to finish.
const stopWait = 10 * time.Second

// stopLocked stops a listener in three steps: stop accepting, signal every
// pipe to reset, and wait for them to close. With resetPipes false (process
// shutdown) it only stops accepting.
func (m *manager) stopLocked(ml *managedListener, resetPipes bool) {
	if !ml.running {
		return
	}
	// 1. Stop accepting. Canceling the context also aborts dials in flight.
	ml.stopAccept()
	_ = ml.ln.Close()
	<-ml.acceptDone
	ml.running = false
	if resetPipes {
		// 2. Signal every pipe to close, and refuse any that were dialing.
		pipes.interruptListener(ml.stats)
		// 3. Wait for every connection goroutine to finish.
		done := make(chan struct{})
		go func() {
			ml.stats.conns.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(stopWait):
			log.Printf("stop %s: connections still closing after %v", ml.stats.labelFor(ml.stats.listen), stopWait)
		}
	}
	changes.notify()
}

func (m *manager) closeAllLocked() {
	for _, ml := range m.list {
		m.stopLocked(ml, false)
	}
}

// shutdown closes every listener; open pipes finish as the process exits.
func (m *manager) shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeAllLocked()
}

// findAnyLocked returns any listener; every listener can be started and
// stopped from the console.
func (m *manager) findAnyLocked(id int) (*managedListener, error) {
	ml := m.findLocked(id)
	if ml == nil {
		return nil, errNotFound
	}
	return ml, nil
}

// editableLocked returns a listener the console may edit or delete: one in
// the config file, when listener management is on.
func (m *manager) editableLocked(id int) (*managedListener, error) {
	if m.policy == nil {
		return nil, errNoManaging
	}
	ml := m.findLocked(id)
	if ml == nil {
		return nil, errNotFound
	}
	if ml.source == sourceRedirect {
		return nil, errRedirect
	}
	if ml.source != sourceConfig {
		return nil, errReadOnly
	}
	return ml, nil
}

// add validates spec, binds it, and saves it to the config file. Nothing is kept if any step
// fails.
func (m *manager) add(spec listenerSpec) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy == nil {
		return 0, errNoManaging
	}
	fw, _, err := buildForwarding(spec)
	if err != nil {
		return 0, err
	}
	if err := m.policy.check(fw); err != nil {
		return 0, err
	}
	if other := m.findListenLocked(fw.listen); other != nil {
		return 0, fmt.Errorf("%s is already used by %s", fw.listen, other.stats.labelFor(other.stats.listen))
	}
	ml := m.appendLocked(fw.stats, sourceConfig, true)
	if err := m.startLocked(ml); err != nil {
		m.list = m.list[:len(m.list)-1]
		return 0, fmt.Errorf("cannot listen on %s: %w", fw.listen, err)
	}
	if err := m.saveLocked(); err != nil {
		m.stopLocked(ml, true)
		m.list = m.list[:len(m.list)-1]
		return 0, err
	}
	return ml.stats.id, nil
}

// start and stop work on every listener. With listener management on, the
// change is saved in the config file; otherwise it lasts until a restart.
func (m *manager) start(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ml, err := m.findAnyLocked(id)
	if err != nil {
		return err
	}
	wasRunning, wasEnabled, lastErr := ml.running, ml.enabled, ml.lastErr
	if err := m.startLocked(ml); err != nil {
		return fmt.Errorf("cannot listen on %s: %w", ml.stats.listen, err)
	}
	ml.enabled = true
	if err := m.saveIfConsoleLocked(ml); err != nil {
		if !wasRunning {
			m.stopLocked(ml, true)
		}
		ml.enabled, ml.lastErr = wasEnabled, lastErr
		changes.notify()
		return err
	}
	return nil
}

func (m *manager) stop(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ml, err := m.findAnyLocked(id)
	if err != nil {
		return err
	}
	// Save the desired state before resetting connections: a failed save
	// must leave the running listener and its existing pipes untouched.
	wasEnabled := ml.enabled
	ml.enabled = false
	if err := m.saveIfConsoleLocked(ml); err != nil {
		ml.enabled = wasEnabled
		return err
	}
	m.stopLocked(ml, true)
	ml.lastErr = ""
	changes.notify()
	log.Printf("stopped %s", ml.stats.labelFor(ml.stats.listen))
	return nil
}

func (m *manager) saveIfConsoleLocked(ml *managedListener) error {
	if m.policy == nil || ml.source != sourceConfig {
		return nil
	}
	return m.saveLocked()
}

func (m *manager) remove(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ml, err := m.editableLocked(id)
	if err != nil {
		return err
	}
	if ml.running {
		return fmt.Errorf("%w before deleting it", errRunning)
	}
	previous := m.list
	for i, x := range m.list {
		if x == ml {
			m.list = append(m.list[:i:i], m.list[i+1:]...)
			break
		}
	}
	if err := m.saveLocked(); err != nil {
		m.list = previous
		return err
	}
	log.Printf("deleted %s", ml.stats.labelFor(ml.stats.listen))
	changes.notify()
	return nil
}

// edit replaces a stopped listener's settings. Its counters carry
// over; it stays stopped until started.
func (m *manager) edit(id int, spec listenerSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ml, err := m.editableLocked(id)
	if err != nil {
		return err
	}
	if ml.running {
		return fmt.Errorf("%w before editing it", errRunning)
	}
	fw, _, err := buildForwarding(spec)
	if err != nil {
		return err
	}
	if err := m.policy.check(fw); err != nil {
		return err
	}
	if other := m.findListenLocked(fw.listen); other != nil && other != ml {
		return fmt.Errorf("%s is already used by %s", fw.listen, other.stats.labelFor(other.stats.listen))
	}
	old, next := ml.stats, fw.stats
	next.id = old.id
	next.accepted.Store(old.accepted.Load())
	next.failed.Store(old.failed.Load())
	next.rejected.Store(old.rejected.Load())
	next.closedUp.Store(old.closedUp.Load())
	next.closedDown.Store(old.closedDown.Load())
	lastErr := ml.lastErr
	ml.stats, ml.lastErr = next, ""
	if err := m.saveLocked(); err != nil {
		ml.stats, ml.lastErr = old, lastErr
		return err
	}
	log.Printf("edited %s -> %s", next.labelFor(next.listen), next.target)
	changes.notify()
	return nil
}

// saveLocked rewrites the config file atomically: the redirect switch and
// [console] exactly as loaded, then every config listener in order. It writes a temporary file in
// the same directory, fsyncs it, and renames it over the old one.
func (m *manager) saveLocked() error {
	fc := fileConfig{EnableHTTPToHTTPSRedirect: m.redirectRaw, Console: m.consoleRaw}
	for _, ml := range m.list {
		if ml.source != sourceConfig {
			continue
		}
		spec := ml.stats.spec
		spec.Enabled = nil
		if !ml.enabled {
			off := false
			spec.Enabled = &off
		}
		fc.Forward = append(fc.Forward, spec)
	}
	var buf bytes.Buffer
	buf.WriteString("# pf-simple configuration. The web console rewrites this file when listeners\n# change, so comments are not kept. Edit it by hand only while pf-simple is\n# stopped.\n\n")
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(fc); err != nil {
		return fmt.Errorf("save listeners: %w", err)
	}
	path := m.configPath
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pf-simple-*.toml")
	if err != nil {
		return fmt.Errorf("save listeners: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err == nil {
		if _, err = tmp.Write(buf.Bytes()); err == nil {
			err = tmp.Sync()
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), path)
		}
		if err != nil {
			return fmt.Errorf("save listeners to %s: %w", path, err)
		}
	} else {
		tmp.Close()
		return fmt.Errorf("save listeners: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// ---------- console view ----------

type manageInfo struct {
	Enabled          bool   `json:"enabled"`
	AllowTargetHosts string `json:"allowTargetHosts"` // "" = no restriction
	AllowTargetPorts string `json:"allowTargetPorts"`
	AllowBindHosts   string `json:"allowBindHosts"`
	AllowBindPorts   string `json:"allowBindPorts"`
}

func (m *manager) info() manageInfo {
	if m.policy == nil {
		return manageInfo{}
	}
	text := func(t interface{ matcherText() string }) string { return t.matcherText() }
	return manageInfo{
		Enabled:          true,
		AllowTargetHosts: text(m.policy.targetHosts),
		AllowTargetPorts: text(m.policy.targetPorts),
		AllowBindHosts:   text(m.policy.bindHosts),
		AllowBindPorts:   text(m.policy.bindPorts),
	}
}

func (m *hostMatcher) matcherText() string {
	if m == nil {
		return ""
	}
	return m.text
}

func (m *portMatcher) matcherText() string {
	if m == nil {
		return ""
	}
	return m.text
}

// snapshot lists every listener with its pipes for the console.
func (m *manager) snapshot() []listenerSnapshot {
	m.mu.Lock()
	stats := make([]*listenerStats, len(m.list))
	type extra struct {
		source, err string
		running     bool
	}
	extras := make([]extra, len(m.list))
	for i, ml := range m.list {
		stats[i] = ml.stats
		extras[i] = extra{ml.source, ml.lastErr, ml.running}
	}
	m.mu.Unlock()
	out := pipes.snapshot(stats)
	for i := range out {
		out[i].Source, out[i].Error, out[i].Running = extras[i].source, extras[i].err, extras[i].running
		// Redirect connections are not pipes; show their live count instead.
		if extras[i].source == sourceRedirect {
			out[i].PipeCount = int(stats[i].active.Load())
		}
	}
	return out
}
