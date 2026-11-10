// Package tunnel holds what pf-simple (the relay) and pf-client share: a
// minimal WebSocket, the stream that carries one TCP connection over it, and
// the client side of ad-hoc tunnels.
package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 implementation. The server side pushes JSON text frames
// to the console and carries tunnels; the client side dials them. The
// standard library has no WebSocket support and this avoids a dependency.

const (
	OpCont   = 0x0
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA

	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	MaxSmallFrame  = 4096    // control messages; the console never sends real data
	maxDataFrame   = 1 << 20 // tunnels send at most chunkSize per frame
	WriteTimeout   = 10 * time.Second
	closeTimeout   = 3 * time.Second
	dialTimeout    = 10 * time.Second
	handshakeLimit = 15 * time.Second
)

// Conn is one WebSocket connection.
type Conn struct {
	conn net.Conn
	rd   *bufio.Reader
	// Header is the server's handshake response, on a dialed connection.
	Header http.Header
	// client is true on the dialing side, which masks what it sends and
	// expects unmasked frames; the server side is the reverse.
	client bool
	// writeTimeout bounds each frame write; zero means none, for tunnel data
	// that the network may hold back for as long as it likes.
	writeTimeout time.Duration
	// readTimeout, when set, is how long the peer may stay silent.
	readTimeout time.Duration

	wmu  sync.Mutex
	wbuf []byte // frame under construction; guarded by wmu

	// dmu orders write deadlines against BeginClose, so a writer cannot
	// clear the closing deadline and then block forever.
	dmu     sync.Mutex
	closing bool
}

// SetTimeouts sets how long the peer may stay silent and how long one frame
// write may take; zero means no limit.
func (c *Conn) SetTimeouts(read, write time.Duration) {
	c.readTimeout, c.writeTimeout = read, write
	if read == 0 {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *Conn) Close() error         { return c.conn.Close() }

func HeaderHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// sameOrigin blocks cross-site WebSocket hijacking: browsers always send
// Origin on WebSocket handshakes, and it must match the console's host.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not a browser
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Upgrade answers a WebSocket handshake and takes over the connection. extra
// headers, if any, go into the 101 response.
func Upgrade(w http.ResponseWriter, r *http.Request, extra http.Header) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !HeaderHasToken(r.Header, "Connection", "upgrade") ||
		!HeaderHasToken(r.Header, "Upgrade", "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || key == "" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not a websocket handshake")
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin websocket refused", http.StatusForbidden)
		return nil, errors.New("cross-origin websocket")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return nil, errors.New("response does not support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n")
	for name, values := range extra {
		for _, v := range values {
			b.WriteString(name + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err = conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, rd: rw.Reader, writeTimeout: WriteTimeout}, nil
}

// StatusError is a handshake the server answered with something other than
// 101.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("the server answered %d %s", e.Code, http.StatusText(e.Code))
	}
	return fmt.Sprintf("%s (%d)", e.Msg, e.Code)
}

// Final reports whether trying again cannot help.
func (e *StatusError) Final() bool {
	return e.Code >= 400 && e.Code < 500 && e.Code != http.StatusTooManyRequests && e.Code != http.StatusRequestTimeout
}

// errorText reads the message out of an error response: pf-simple sends
// {"error": "..."}, a proxy in front of it may send anything.
func errorText(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 2048))
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
		return parsed.Error
	}
	if text := strings.TrimSpace(string(raw)); len(text) < 200 && !strings.Contains(text, "<") {
		return text
	}
	return ""
}

// Dial opens a WebSocket to an https URL.
func Dial(ctx context.Context, rawURL string, header http.Header, tlsConfig *tls.Config) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("only https URLs are supported")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{}
	if tlsConfig != nil {
		cfg = tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	cfg.NextProtos = []string{"http/1.1"}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	for name, values := range header {
		req.Header[name] = values
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("User-Agent", "pf-client")
	_ = conn.SetDeadline(time.Now().Add(handshakeLimit))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg := errorText(resp.Body)
		resp.Body.Close()
		conn.Close()
		return nil, &StatusError{Code: resp.StatusCode, Msg: msg}
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		conn.Close()
		return nil, errors.New("the server's websocket handshake is invalid")
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, rd: rd, Header: resp.Header, client: true, writeTimeout: WriteTimeout}, nil
}

func (c *Conn) WriteFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	buf := append(c.wbuf[:0], 0x80|op) // FIN
	var maskBit byte
	if c.client {
		maskBit = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n <= 0xFFFF:
		buf = append(buf, maskBit|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, maskBit|127)
		buf = binary.BigEndian.AppendUint64(buf, uint64(n))
	}
	if c.client {
		var mask [4]byte
		binary.BigEndian.PutUint32(mask[:], mrand.Uint32())
		buf = append(buf, mask[:]...)
		at := len(buf)
		buf = append(buf, payload...)
		for i, body := 0, buf[at:]; i < len(body); i++ {
			body[i] ^= mask[i%4]
		}
	} else {
		buf = append(buf, payload...)
	}
	c.wbuf = buf

	c.dmu.Lock()
	switch {
	case c.closing:
		_ = c.conn.SetWriteDeadline(time.Now().Add(closeTimeout))
	case c.writeTimeout > 0:
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	default:
		_ = c.conn.SetWriteDeadline(time.Time{})
	}
	c.dmu.Unlock()
	_, err := c.conn.Write(buf)
	return err
}

// BeginClose bounds every write from now on, including one already blocked.
func (c *Conn) BeginClose() {
	c.dmu.Lock()
	c.closing = true
	_ = c.conn.SetWriteDeadline(time.Now().Add(closeTimeout))
	c.dmu.Unlock()
}

// frame is the header of the frame being read; left and at track how much of
// its payload readBody has yet to deliver.
type frame struct {
	op     byte
	left   uint64
	masked bool
	mask   [4]byte
	at     int
}

func (c *Conn) readHeader() (frame, error) {
	if c.readTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	}
	var b [8]byte
	var f frame
	if _, err := io.ReadFull(c.rd, b[:2]); err != nil {
		return f, err
	}
	f.op = b[0] & 0x0F
	f.masked = b[1]&0x80 != 0
	if f.masked == c.client {
		if c.client {
			return f, errors.New("masked server frame")
		}
		return f, errors.New("unmasked client frame")
	}
	f.left = uint64(b[1] & 0x7F)
	switch f.left {
	case 126:
		if _, err := io.ReadFull(c.rd, b[:2]); err != nil {
			return f, err
		}
		f.left = uint64(binary.BigEndian.Uint16(b[:2]))
	case 127:
		if _, err := io.ReadFull(c.rd, b[:8]); err != nil {
			return f, err
		}
		f.left = binary.BigEndian.Uint64(b[:8])
	}
	if f.masked {
		if _, err := io.ReadFull(c.rd, f.mask[:]); err != nil {
			return f, err
		}
	}
	return f, nil
}

// readBody reads some of the frame's remaining payload into p.
func (c *Conn) readBody(f *frame, p []byte) (int, error) {
	if uint64(len(p)) > f.left {
		p = p[:f.left]
	}
	if c.readTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	}
	n, err := c.rd.Read(p)
	if f.masked {
		for i := 0; i < n; i++ {
			p[i] ^= f.mask[(f.at+i)%4]
		}
		f.at = (f.at + n) % 4
	}
	f.left -= uint64(n)
	if n > 0 {
		return n, nil
	}
	return 0, err
}

func (c *Conn) readPayload(f frame, max uint64) ([]byte, error) {
	if f.left > max {
		return nil, errors.New("frame too large")
	}
	payload := make([]byte, f.left)
	for off := 0; off < len(payload); {
		n, err := c.readBody(&f, payload[off:])
		if err != nil {
			return nil, err
		}
		off += n
	}
	return payload, nil
}

// Next returns the next text or binary frame. It answers pings, skips pongs
// and returns io.EOF when the peer closes.
func (c *Conn) Next(max uint64) (op byte, payload []byte, err error) {
	for {
		f, err := c.readHeader()
		if err != nil {
			return 0, nil, err
		}
		payload, err := c.readPayload(f, max)
		if err != nil {
			return 0, nil, err
		}
		switch f.op {
		case OpClose:
			_ = c.WriteFrame(OpClose, payload[:min(len(payload), 2)])
			return 0, nil, io.EOF
		case OpPing:
			if err := c.WriteFrame(OpPong, payload); err != nil {
				return 0, nil, err
			}
		case OpPong:
		default:
			return f.op, payload, nil
		}
	}
}

// ReadLoop answers pings and returns when the peer closes or errors.
func (c *Conn) ReadLoop() error {
	for {
		if _, _, err := c.Next(MaxSmallFrame); err != nil {
			return err
		}
	}
}
