package main

// The flow log: every connection from accept to close, for the console's
// Flow log tab. A short connection is over before a state push can show it;
// here it is not missed. While a page watches, each connection's open and
// close events go to a broadcasting queue (drop-oldest, so a slow page never
// holds up the forwarder). Every flowSnapshotInterval the page also gets the
// authoritative list of open connections, which repairs whatever a dropped
// event lost. The last flowHistory closed connections are kept, so a page
// opened later, or GET api/flows, starts with them.

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	queue "github.com/wushilin/go-named-queue"
)

const (
	flowQueue            = "console.flows"
	flowQueueCapacity    = 4096 // events a slow page may lag behind; older ones are dropped
	flowHistory          = 2000 // closed connections kept
	flowSnapshotInterval = 5 * time.Second
	flowBatch            = 512  // events per WebSocket message at most
	maxSnapshotFlows     = 5000 // open connections per snapshot; "truncated" says when there are more
)

// Flow results, once a connection has ended.
const (
	flowClosed  = "closed"  // both sides finished normally
	flowReset   = "reset"   // reset from the console, or its listener stopped
	flowIdle    = "idle"    // one side finished and the other stayed idle too long
	flowFailed  = "failed"  // the target could not be reached
	flowRefused = "refused" // over max_connections, or the listener was stopping
)

// connIDs numbers every accepted connection, so refused and failed ones get
// an id in the flow log too. A pipe keeps its connection's id.
var connIDs atomic.Uint64

type flowView struct {
	ID uint64 `json:"id"`
	// Seq orders views of the same connection: a page keeps the one with the
	// highest, so a snapshot taken just before an event cannot undo it.
	Seq            uint64 `json:"seq"`
	ListenerID     int    `json:"listenerId"`
	Listener       string `json:"listener"` // name [listen], or listen
	Target         string `json:"target"`
	Client         string `json:"client"`
	Local          string `json:"local"`
	UpstreamLocal  string `json:"upstreamLocal,omitempty"`
	UpstreamRemote string `json:"upstreamRemote,omitempty"`
	Started        int64  `json:"started"`         // unix ms
	Ended          int64  `json:"ended,omitempty"` // unix ms; 0 while open
	BytesUp        uint64 `json:"bytesUp"`         // delivered to the target
	BytesDown      uint64 `json:"bytesDown"`       // delivered to the client
	Result         string `json:"result,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type flowEvent struct {
	Type string   `json:"type"` // open or close
	Flow flowView `json:"flow"`
}

type flowLog struct {
	queues  *queue.QueueRegistry
	events  *queue.Sender[[]byte]
	viewers atomic.Int32 // pages watching; no event is built while zero

	// The last flowHistory closed connections, written without a lock: each
	// close takes the next slot with one atomic add and publishes its view
	// into it. Readers see each slot's latest view, whole.
	closed [flowHistory]atomic.Pointer[flowView]
	next   atomic.Uint64
}

var flows = newFlowLog()

func newFlowLog() *flowLog {
	f := &flowLog{queues: queue.NewRegistry()}
	if err := queue.CreateBroadcastingWithFullAction[[]byte](f.queues, flowQueue, flowQueueCapacity, queue.FullDropOldest); err != nil {
		panic(err) // a fresh registry cannot already hold the queue
	}
	f.events, _ = queue.AcquireSender[[]byte](f.queues, flowQueue)
	return f
}

var flowSeq atomic.Uint64

// flow describes p as it is now.
func (p *pipe) flow() flowView {
	l := p.listener
	return flowView{
		ID: p.id, Seq: flowSeq.Add(1), ListenerID: l.id, Listener: l.labelFor(l.listen), Target: l.target,
		Client: p.client.RemoteAddr().String(), Local: p.client.LocalAddr().String(),
		UpstreamLocal: p.upstream.LocalAddr().String(), UpstreamRemote: p.upstream.RemoteAddr().String(),
		Started: p.started.UnixMilli(), BytesUp: p.up.written.Load(), BytesDown: p.down.written.Load(),
	}
}

// opened tells the watching pages about a new pipe.
func (f *flowLog) opened(p *pipe) {
	if f.viewers.Load() > 0 {
		f.publish(flowEvent{Type: "open", Flow: p.flow()})
	}
}

// ended records a pipe that closed, with how it ended.
func (f *flowLog) ended(p *pipe, idle bool) {
	v := p.flow()
	v.Ended = time.Now().UnixMilli()
	switch {
	case p.interrupted.Load():
		v.Result = flowReset
		if r := p.resetReason.Load(); r != nil {
			v.Reason = *r
		}
	case idle:
		v.Result, v.Reason = flowIdle, "half-closed and idle for "+halfCloseIdleTimeout.String()
	default:
		v.Result = flowClosed
	}
	f.record(v)
}

// refused records a connection that never became a pipe: it opens and
// closes at once.
func (f *flowLog) refused(id uint64, l *listenerStats, start time.Time, client net.Conn, result, reason string) {
	f.record(flowView{
		ID: id, Seq: flowSeq.Add(1), ListenerID: l.id, Listener: l.labelFor(l.listen), Target: l.target,
		Client: client.RemoteAddr().String(), Local: client.LocalAddr().String(),
		Started: start.UnixMilli(), Ended: time.Now().UnixMilli(), Result: result, Reason: reason,
	})
}

func (f *flowLog) record(v flowView) {
	f.closed[(f.next.Add(1)-1)%flowHistory].Store(&v)
	if f.viewers.Load() > 0 {
		f.publish(flowEvent{Type: "close", Flow: v})
	}
}

func (f *flowLog) publish(ev flowEvent) {
	if data, err := json.Marshal(ev); err == nil {
		_ = f.events.Send(data) // never blocks: drop-oldest
	}
}

// closedSince returns the kept closed connections that ended at or after
// since (unix ms), oldest first.
func (f *flowLog) closedSince(since int64) []flowView {
	out := []flowView{}
	for i := range f.closed {
		if v := f.closed[i].Load(); v != nil && v.Ended >= since {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ended != out[j].Ended {
			return out[i].Ended < out[j].Ended
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

type flowSnapshot struct {
	Type string `json:"type"` // snapshot
	Now  int64  `json:"now"`
	Full bool   `json:"full"` // the first one: closed holds the whole history
	// Seq was taken before the open connections were listed. An open view a
	// page holds with a higher seq is newer than this list, so a page drops a
	// connection missing from Active only when its view is at or below Seq.
	Seq       uint64     `json:"seq"`
	Active    []flowView `json:"active"`
	Truncated bool       `json:"truncated"` // more were open than are listed
	Closed    []flowView `json:"closed"`
}

// flowSnapshot lists the open connections, and those closed since since.
func (f *flowLog) snapshot(since int64, full bool) flowSnapshot {
	seq := flowSeq.Load()
	live, truncated := pipes.list(maxSnapshotFlows)
	snap := flowSnapshot{Type: "snapshot", Full: full, Seq: seq, Active: make([]flowView, 0, len(live)), Truncated: truncated}
	for _, p := range live {
		snap.Active = append(snap.Active, p.flow())
	}
	snap.Closed = f.closedSince(since)
	snap.Now = time.Now().UnixMilli()
	return snap
}

// handleFlows serves GET api/flows: a WebSocket stream for the Flow log tab,
// or, for a plain request, one snapshot as JSON. ?since= (unix ms) limits the
// closed connections returned.
func (s *consoleServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	if !headerHasToken(r.Header, "Upgrade", "websocket") {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		snap := flows.snapshot(since, true)
		writeJSON(w, snap)
		return
	}
	ws, quit, ok := s.openSocket(w, r)
	if !ok {
		return
	}
	defer ws.Close()
	// Subscribe before the first snapshot, so nothing falls between them.
	rx, err := queue.AcquireReceiver[[]byte](flows.queues, flowQueue)
	if err != nil {
		return
	}
	defer rx.Close()
	flows.viewers.Add(1)
	defer flows.viewers.Add(-1)

	first := flows.snapshot(0, true)
	data, err := json.Marshal(first)
	if err != nil || ws.writeFrame(wsOpText, data) != nil {
		return
	}
	done := make(chan struct{})
	defer close(done)
	// Recv cannot be cancelled, so a watcher closes the receiver when the page
	// leaves, its session ends or a write fails. It also sends the snapshots
	// and the pings.
	go func() {
		ping := time.NewTicker(wsPingInterval)
		snap := time.NewTicker(flowSnapshotInterval)
		defer ping.Stop()
		defer snap.Stop()
		last := first.Now
		for {
			select {
			case <-quit:
			case <-done:
			case <-ping.C:
				if ws.writeFrame(wsOpPing, nil) == nil {
					continue
				}
			case <-snap.C:
				// Overlap the previous snapshot by a second: a connection
				// closing while it was built is listed by one of them.
				s := flows.snapshot(last-1000, false)
				last = s.Now
				if data, err := json.Marshal(s); err == nil && ws.writeFrame(wsOpText, data) == nil {
					continue
				}
			}
			rx.Close()
			return
		}
	}()
	var msg bytes.Buffer
	for {
		ev, err := rx.Recv()
		if err != nil {
			return
		}
		// Whatever else is waiting goes in the same message.
		msg.Reset()
		msg.WriteString(`{"type":"events","events":[`)
		msg.Write(ev)
		for n := 1; n < flowBatch; n++ {
			more, err := rx.TryRecv()
			if err != nil {
				break
			}
			msg.WriteByte(',')
			msg.Write(more)
		}
		msg.WriteString("]}")
		if ws.writeFrame(wsOpText, msg.Bytes()) != nil {
			return
		}
	}
}
