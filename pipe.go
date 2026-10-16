package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// changes wakes the console when anything it shows has changed. Writers only
// pay for an atomic swap; the channel send happens once per dirty period.
var changes = &changeSignal{wake: make(chan struct{}, 1)}

type changeSignal struct {
	dirty atomic.Bool
	wake  chan struct{}
}

func (c *changeSignal) notify() {
	// Load first: while already dirty this stays a shared-cache read, so
	// copy loops on many cores do not bounce the cache line.
	if c.dirty.Load() {
		return
	}
	if !c.dirty.Swap(true) {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

// flow counts one direction of a pipe. read is what the source socket gave
// us; written is what reached the destination socket.
type flow struct {
	read     atomic.Uint64
	written  atomic.Uint64
	done     atomic.Bool // the source reached EOF or the copy failed
	activity func()
	// Speed limits for this direction: the listener's shared total and this
	// pipe's own cap. Either may be nil; both are enforced.
	total   *limiter
	perConn *limiter
	cancel  chan struct{} // closed when the pipe ends; wakes a limited wait
}

// chunk is the most bytes one read or splice may move in this direction.
func (f *flow) chunk() int {
	n := copyChunkSize
	for _, l := range []*limiter{f.total, f.perConn} {
		if l != nil {
			n = min(n, limitedChunk(l.rate))
		}
	}
	return n
}

// throttle waits until n more bytes fit both limits.
func (f *flow) throttle(n int64) {
	waitAll(n, f.cancel, f.total, f.perConn)
}

func (f *flow) gotRead(n int64) {
	if n > 0 {
		f.read.Add(uint64(n))
	}
}

func (f *flow) wrote(n int64) {
	if n <= 0 {
		return
	}
	f.written.Add(uint64(n))
	if f.activity != nil {
		f.activity()
	}
	changes.notify()
}

// finish marks the source side of this direction as closed.
func (f *flow) finish() {
	f.done.Store(true)
	changes.notify()
}

// pipe is one forwarded connection: the client leg and the upstream leg.
type pipe struct {
	id          uint64
	listener    *listenerStats
	started     time.Time
	client      net.Conn
	upstream    net.Conn
	up          flow // client -> upstream
	down        flow // upstream -> client
	interrupted atomic.Bool
	ended       chan struct{} // closed by end(); shared by both flows' cancel
	endOnce     sync.Once
}

// end wakes any copy goroutine waiting on a rate limit.
func (p *pipe) end() { p.endOnce.Do(func() { close(p.ended) }) }

// interrupt resets both legs: SO_LINGER 0 makes Close send RST instead of
// FIN, and closing the sockets wakes both copy goroutines. Linger is set on
// both sockets before either is closed, and the copy goroutines skip their
// CloseWrite once interrupted, so neither peer sees a FIN before the RST.
func (p *pipe) interrupt() {
	if !p.interrupted.CompareAndSwap(false, true) {
		return
	}
	changes.notify()
	p.end()
	legs := []net.Conn{p.client, p.upstream}
	for _, conn := range legs {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
	}
	for _, conn := range legs {
		_ = conn.Close()
	}
}

func (l *listenerStats) labelFor(addr string) string {
	if l.name == "" {
		return addr
	}
	return l.name + " [" + addr + "]"
}

// limitsNote describes configured limits for the startup log.
func (l *listenerStats) limitsNote() string {
	var parts []string
	if l.totalRate > 0 {
		parts = append(parts, "total "+fmtByteRate(l.totalRate))
	}
	if l.perConnRate > 0 {
		parts = append(parts, fmtByteRate(l.perConnRate)+" per connection")
	}
	if l.maxConns > 0 {
		parts = append(parts, fmt.Sprintf("max %d connections", l.maxConns))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// admit reserves a connection slot, or reports false when max_connections
// is reached. Every admitted connection must call release.
func (l *listenerStats) admit() bool {
	n := l.active.Add(1)
	if l.maxConns > 0 && n > l.maxConns {
		l.active.Add(-1)
		return false
	}
	return true
}

func (l *listenerStats) release() { l.active.Add(-1) }

// listenerStats holds the counters of one --forward mapping.
type listenerStats struct {
	id       int
	spec     listenerSpec // as configured; written back to the state file
	name     string       // optional label from the config file
	listen   string
	target   string
	accepted atomic.Uint64
	failed   atomic.Uint64 // upstream dial failures
	rejected atomic.Uint64 // refused because max_connections was reached
	// active counts connections from accept until close, including those
	// still dialing upstream; it enforces maxConns.
	active   atomic.Int64
	maxConns int64 // 0 = unlimited
	// conns counts handleConnection goroutines so a stop can wait for them;
	// closing refuses new pipes while a stop is in progress.
	conns   sync.WaitGroup
	closing atomic.Bool
	// totalUp and totalDown are shared by all pipes of this forward, one per
	// direction; perConnRate (bytes/s) gives each pipe its own limiter per
	// direction. Zero values mean unlimited.
	totalUp     *limiter
	totalDown   *limiter
	totalRate   float64
	perConnRate float64
	// Bytes delivered by pipes that already closed; live pipes are added at
	// snapshot time.
	closedUp   atomic.Uint64
	closedDown atomic.Uint64
}

func newListenerStats(id int, listen, target string) *listenerStats {
	return &listenerStats{id: id, listen: listen, target: target}
}

// pipeRegistry tracks every live pipe. The mutex is only held to add, remove
// or list pipes; byte counters are atomics updated without it.
type pipeRegistry struct {
	mu     sync.Mutex
	nextID uint64
	pipes  map[uint64]*pipe
}

var pipes = &pipeRegistry{pipes: make(map[uint64]*pipe)}

func (r *pipeRegistry) add(l *listenerStats, client, upstream net.Conn) *pipe {
	p := &pipe{listener: l, started: time.Now(), client: client, upstream: upstream, ended: make(chan struct{})}
	p.up.total, p.up.perConn, p.up.cancel = l.totalUp, newLimiter(l.perConnRate), p.ended
	p.down.total, p.down.perConn, p.down.cancel = l.totalDown, newLimiter(l.perConnRate), p.ended
	r.mu.Lock()
	if l.closing.Load() {
		r.mu.Unlock()
		return nil
	}
	r.nextID++
	p.id = r.nextID
	r.pipes[p.id] = p
	r.mu.Unlock()
	changes.notify()
	return p
}

func (r *pipeRegistry) remove(p *pipe) {
	r.mu.Lock()
	delete(r.pipes, p.id)
	// Fold totals in under the lock so a concurrent snapshot never counts a
	// pipe twice or misses it.
	p.listener.closedUp.Add(p.up.written.Load())
	p.listener.closedDown.Add(p.down.written.Load())
	r.mu.Unlock()
	changes.notify()
}

// interruptListener resets every open pipe of one listener and refuses new
// ones. closing is set under the registry lock, so a connection that was
// still dialing cannot register after the sweep and slip through.
func (r *pipeRegistry) interruptListener(l *listenerStats) {
	r.mu.Lock()
	l.closing.Store(true)
	var victims []*pipe
	for _, p := range r.pipes {
		if p.listener == l {
			victims = append(victims, p)
		}
	}
	r.mu.Unlock()
	for _, p := range victims {
		p.interrupt()
	}
}

func (r *pipeRegistry) get(id uint64) *pipe {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pipes[id]
}

// Snapshot types are the console's JSON API.

type pipeSnapshot struct {
	ID             uint64 `json:"id"`
	Started        int64  `json:"started"` // unix milliseconds
	ClientRemote   string `json:"clientRemote"`
	ClientLocal    string `json:"clientLocal"`
	UpstreamLocal  string `json:"upstreamLocal"`
	UpstreamRemote string `json:"upstreamRemote"`
	ClientToPF     uint64 `json:"clientToPf"`
	PFToUpstream   uint64 `json:"pfToUpstream"`
	UpstreamToPF   uint64 `json:"upstreamToPf"`
	PFToClient     uint64 `json:"pfToClient"`
	UpDone         bool   `json:"upDone"`
	DownDone       bool   `json:"downDone"`
	Interrupted    bool   `json:"interrupted"`
}

// maxSnapshotPipes bounds each listener's pipe list in a console push, so a
// listener with thousands of connections cannot flood the browser. PipeCount
// still reports the true number.
const maxSnapshotPipes = 500

type listenerSnapshot struct {
	ID        int          `json:"id"`
	Source    string       `json:"source"` // "config" or "console"
	Running   bool         `json:"running"`
	Error     string       `json:"error,omitempty"`
	Spec      listenerSpec `json:"spec"` // as configured, for the edit form
	Name      string       `json:"name"`
	Rejected  uint64       `json:"rejected"`
	MaxConns  int64        `json:"maxConns"` // 0 = unlimited
	PipeCount int          `json:"pipeCount"`
	Listen    string       `json:"listen"`
	Target    string       `json:"target"`
	Accepted  uint64       `json:"accepted"`
	Failed    uint64       `json:"failed"`
	BytesUp   uint64       `json:"bytesUp"` // delivered upstream, closed + live
	BytesDown uint64       `json:"bytesDown"`
	// Speed limits in bytes per second, per direction; 0 = unlimited.
	TotalSpeed   float64        `json:"totalSpeed"`
	PerConnSpeed float64        `json:"perConnSpeed"`
	Pipes        []pipeSnapshot `json:"pipes"`
}

func (r *pipeRegistry) snapshot(listeners []*listenerStats) []listenerSnapshot {
	out := make([]listenerSnapshot, len(listeners))
	byID := make(map[*listenerStats]*listenerSnapshot, len(listeners))
	for i, l := range listeners {
		out[i] = listenerSnapshot{
			Spec: l.spec,
			ID:   l.id, Name: l.name, Listen: l.listen, Target: l.target,
			Rejected: l.rejected.Load(), MaxConns: l.maxConns,
			Accepted: l.accepted.Load(), Failed: l.failed.Load(),
			TotalSpeed: l.totalRate, PerConnSpeed: l.perConnRate,
			Pipes: []pipeSnapshot{},
		}
		byID[l] = &out[i]
	}

	r.mu.Lock()
	live := make([]*pipe, 0, len(r.pipes))
	for _, p := range r.pipes {
		live = append(live, p)
	}
	for i, l := range listeners {
		out[i].BytesUp = l.closedUp.Load()
		out[i].BytesDown = l.closedDown.Load()
	}
	for _, p := range live {
		if ls := byID[p.listener]; ls != nil {
			ls.BytesUp += p.up.written.Load()
			ls.BytesDown += p.down.written.Load()
		}
	}
	r.mu.Unlock()

	sort.Slice(live, func(i, j int) bool { return live[i].id < live[j].id })
	for _, p := range live {
		ls := byID[p.listener]
		if ls == nil {
			continue
		}
		ls.Pipes = append(ls.Pipes, pipeSnapshot{
			ID:             p.id,
			Started:        p.started.UnixMilli(),
			ClientRemote:   p.client.RemoteAddr().String(),
			ClientLocal:    p.client.LocalAddr().String(),
			UpstreamLocal:  p.upstream.LocalAddr().String(),
			UpstreamRemote: p.upstream.RemoteAddr().String(),
			ClientToPF:     p.up.read.Load(),
			PFToUpstream:   p.up.written.Load(),
			UpstreamToPF:   p.down.read.Load(),
			PFToClient:     p.down.written.Load(),
			UpDone:         p.up.done.Load(),
			DownDone:       p.down.done.Load(),
			Interrupted:    p.interrupted.Load(),
		})
	}
	for i := range out {
		out[i].PipeCount = len(out[i].Pipes)
		if n := len(out[i].Pipes); n > maxSnapshotPipes {
			out[i].Pipes = out[i].Pipes[n-maxSnapshotPipes:] // keep the newest
		}
	}
	return out
}
