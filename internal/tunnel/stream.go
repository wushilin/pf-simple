package tunnel

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// A Stream carries one TCP connection over one WebSocket, and lives exactly
// as long as that WebSocket: nothing is buffered or resumed, so a broken
// link ends the connection, as a broken TCP connection would.
//
//	binary            the bytes, in order
//	text "eof"        a half-close: the sender's FIN
//	text "err:why"    the stream is being dropped, and why
//	close             the closing handshake after a clean finish
//	ping              keepalive; sent by both ends on a timer, never answered
//
// Flow control is TCP's own: a Write blocks while the WebSocket's socket is
// full, and a reader that stops reading stops the far end's writes.

const (
	chunkSize = 64 << 10

	msgEOF       = "eof"
	msgErrPrefix = "err:"
)

// Timing; variables so tests can shorten them.
var (
	// pingEvery keeps an idle stream alive through a reverse proxy. An end
	// that hears nothing for linkSilence, not even a ping, treats the link
	// as dead: three pings in a row went missing.
	pingEvery   = 10 * time.Second
	linkSilence = 30 * time.Second
)

var ErrPeerClosed = errors.New("closed by the other side")

// cleanReason makes a reason that arrived over the wire safe to log and
// pass on: it comes from the far end, which may be another party's
// pf-client, so it is cut short and stripped of anything unprintable.
func cleanReason(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 200 {
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RemoteError is the reason the far end gave for dropping the stream.
type RemoteError struct{ Reason string }

func (e *RemoteError) Error() string { return e.Reason }

// Stream implements net.Conn, plus CloseWrite, so the code that pipes TCP
// connections pipes these too.
type Stream struct {
	c   *Conn
	cur frame // the data frame being read; only the reader touches it

	remote net.Addr // set by SetRemote

	readEOF   atomic.Bool
	wroteEOF  atomic.Bool
	done      chan struct{} // closed by Close
	closeOnce sync.Once
	closed    atomic.Bool // Close has begun: errors from here on are our own doing
	// gone is closed when, after the far end's half-close, the far end also
	// closes the stream or the link dies. See watch.
	gone       chan struct{}
	goneReason atomic.Pointer[string] // what the far end said then, if anything
	failure    atomic.Pointer[error]  // the first error Read returned

	// CloseReason, if set before the stream is used, is asked when the
	// stream is cut rather than finished cleanly; what it returns is sent
	// to the far end as the reason, so that end's log can say what broke.
	CloseReason func() string
}

// NewStream takes over c. The pings come from their own timer rather than
// in reply to the peer's, so reading never has to write and the two
// directions stay independent.
func NewStream(c *Conn) *Stream {
	c.SetTimeouts(linkSilence, 0)
	s := &Stream{c: c, done: make(chan struct{}), gone: make(chan struct{})}
	go func() {
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				if c.WriteFrame(OpPing, nil) != nil {
					_ = c.Close() // wake whoever is reading
					return
				}
			}
		}
	}()
	return s
}

// Read returns stream bytes, and io.EOF only for the far end's half-close.
// A link that simply ends, however politely, is a broken stream and an
// error: taking it for a half-close would leave this end waiting on a
// stream that no longer exists.
func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.read(p)
	if err == io.EOF && !s.readEOF.Load() {
		err = io.ErrUnexpectedEOF
	}
	if err != nil && err != io.EOF && !s.closed.Load() {
		s.failure.CompareAndSwap(nil, &err)
	}
	return n, err
}

// Failure is the error that broke the stream for its reader: the far end's
// reason (a *RemoteError), a lost or silent link, or nil.
func (s *Stream) Failure() error {
	if err := s.failure.Load(); err != nil {
		return *err
	}
	return nil
}

// HalfClosed reports whether the far end has half-closed.
func (s *Stream) HalfClosed() bool { return s.readEOF.Load() }

func (s *Stream) read(p []byte) (int, error) {
	for s.cur.left == 0 {
		if s.readEOF.Load() {
			return 0, io.EOF
		}
		f, err := s.c.readHeader()
		if err != nil {
			return 0, err
		}
		if f.op == OpBinary || f.op == OpCont {
			if f.left > maxDataFrame {
				return 0, errors.New("frame too large")
			}
			s.cur = f
			continue
		}
		payload, err := s.c.readPayload(f, 1024)
		if err != nil {
			return 0, err
		}
		switch f.op {
		case OpText:
			if string(payload) == msgEOF {
				s.readEOF.Store(true)
				go s.watch()
				return 0, io.EOF
			}
			if msg, ok := strings.CutPrefix(string(payload), msgErrPrefix); ok {
				return 0, &RemoteError{Reason: cleanReason(msg)}
			}
		case OpClose:
			return 0, ErrPeerClosed
		}
	}
	return s.c.readBody(&s.cur, p)
}

// watch keeps reading after the far end's half-close. Nothing more is due
// except pings and the final close, but without a reader nobody would learn
// that the far end closed the stream or that the link died, and an end that
// is still sending into an idle stream would hold its socket open for ever.
func (s *Stream) watch() {
	defer close(s.gone)
	for {
		f, err := s.c.readHeader()
		if err != nil {
			return
		}
		if f.op == OpBinary || f.op == OpCont {
			return // nothing may follow a half-close: a broken or hostile peer
		}
		payload, err := s.c.readPayload(f, 1024)
		if err != nil || f.op == OpClose {
			return
		}
		if msg, ok := strings.CutPrefix(string(payload), msgErrPrefix); ok && f.op == OpText {
			msg = cleanReason(msg)
			s.goneReason.Store(&msg)
		}
	}
}

// GoneReason is why the far end said it was closing, once Gone is closed;
// empty if it did not say.
func (s *Stream) GoneReason() string {
	if r := s.goneReason.Load(); r != nil {
		return *r
	}
	return ""
}

// Gone is closed once the far end, having half-closed, is gone for good:
// it closed the stream or the link died. Until the far end's half-close it
// stays open, and Read reports such failures instead.
func (s *Stream) Gone() <-chan struct{} { return s.gone }

func (s *Stream) Write(p []byte) (int, error) {
	for off := 0; off < len(p); off += chunkSize {
		if err := s.c.WriteFrame(OpBinary, p[off:min(off+chunkSize, len(p))]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// CloseWrite half-closes: the far end reads io.EOF after the bytes written
// so far, and may keep sending.
func (s *Stream) CloseWrite() error {
	if !s.wroteEOF.CompareAndSwap(false, true) {
		return nil
	}
	return s.c.WriteFrame(OpText, []byte(msgEOF))
}

// Fail drops the stream and tells the far end why.
func (s *Stream) Fail(reason string) {
	s.CloseReason = nil // this reason, not the usual one
	s.c.BeginClose()
	_ = s.c.WriteFrame(OpText, []byte(msgErrPrefix+reason))
	_ = s.c.WriteFrame(OpClose, nil)
	_ = s.Close()
}

// Close ends the stream. After a clean finish (both half-closes exchanged)
// it does the WebSocket closing handshake and waits briefly for the far
// end's reply: closing the socket at once could reset it while the far end
// is still reading the last bytes. Any other close cuts the stream at once.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		s.c.BeginClose()
		if s.readEOF.Load() && s.wroteEOF.Load() {
			if s.c.WriteFrame(OpClose, nil) == nil {
				t := time.NewTimer(closeTimeout)
				select {
				case <-s.gone: // watch saw the far end's close
				case <-t.C:
				}
				t.Stop()
			}
		} else if s.CloseReason != nil {
			if reason := s.CloseReason(); reason != "" {
				_ = s.c.WriteFrame(OpText, []byte(msgErrPrefix+reason))
				_ = s.c.WriteFrame(OpClose, nil)
			}
		}
		_ = s.c.Close()
	})
	return nil
}

// SetRemote replaces what RemoteAddr reports, for a peer that arrived
// through a reverse proxy. Call it before the stream is shared.
func (s *Stream) SetRemote(addr string) { s.remote = labelAddr(addr) }

type labelAddr string

func (a labelAddr) Network() string { return "tcp" }
func (a labelAddr) String() string  { return string(a) }

func (s *Stream) LocalAddr() net.Addr { return s.c.LocalAddr() }

func (s *Stream) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	return s.c.RemoteAddr()
}

func (s *Stream) SetDeadline(t time.Time) error      { return s.c.conn.SetDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error  { return s.c.conn.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.c.conn.SetWriteDeadline(t) }
