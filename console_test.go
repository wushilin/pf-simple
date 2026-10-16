package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseConsole(t *testing.T) {
	cases := []struct {
		value, env, addr, password string
	}{
		{"0.0.0.0:18222@xyz123", "envpw", "0.0.0.0:18222", "xyz123"},
		{"0.0.0.0:18222@p@ss", "", "0.0.0.0:18222", "p@ss"},
		{"0.0.0.0:18222", "envpw", "0.0.0.0:18222", "envpw"},
		{"0.0.0.0:18222@", "envpw", "0.0.0.0:18222", "envpw"},
		{"[::1]:18222", "", "[::1]:18222", ""},
	}
	for _, c := range cases {
		addr, pw, err := parseConsole(c.value, c.env)
		if err != nil || addr != c.addr || pw != c.password {
			t.Errorf("parseConsole(%q, %q) = %q, %q, %v", c.value, c.env, addr, pw, err)
		}
	}
	if _, _, err := parseConsole("nonsense@pw", ""); err == nil {
		t.Error("expected an error for a bad address")
	}
}

// startConsole runs a console and a forwarder that feed the same stats.
func startConsole(t *testing.T, password, target string) (consoleURL, forwardAddr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fln.Close() })
	stats := newListenerStats(0, fln.Addr().String(), target)
	go acceptConnections(ctx, fln, stats, halfCloseIdleTimeout)

	cs := newConsoleServer("", password, newManager([]forwarding{{stats: stats}}, nil, halfCloseIdleTimeout))
	cln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go cs.serve(ctx, cln)
	return "http://" + cln.Addr().String(), fln.Addr().String()
}

func post(t *testing.T, url, cookie, body string, csrf bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if csrf {
		req.Header.Set(csrfHeader, "1")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func get(t *testing.T, url, cookie string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestConsoleAuth(t *testing.T) {
	base, _ := startConsole(t, "xyz123", "127.0.0.1:1")

	if r := get(t, base+"/api/state", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state without session: %d", r.StatusCode)
	}
	if r := get(t, base+"/", ""); r.StatusCode != http.StatusOK || r.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("index: %d csp=%q", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}
	if r := post(t, base+"/api/login", "", `{"password":"xyz123"}`, false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("login without CSRF header: %d", r.StatusCode)
	}
	if r := post(t, base+"/api/login", "", `{"password":"nope"}`, true); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	r := post(t, base+"/api/login", "", `{"password":"xyz123"}`, true)
	if r.StatusCode != http.StatusNoContent || len(r.Cookies()) != 1 {
		t.Fatalf("login: %d cookies=%v", r.StatusCode, r.Cookies())
	}
	c := r.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", c)
	}
	if !strings.HasPrefix(c.Name, sessionCookiePrefix) || c.Name == sessionCookiePrefix {
		t.Fatalf("cookie should be named after the console port: %q", c.Name)
	}
	cookie := c.Name + "=" + c.Value
	if r := get(t, base+"/api/state", cookie); r.StatusCode != http.StatusOK {
		t.Fatalf("state with session: %d", r.StatusCode)
	}
	post(t, base+"/api/logout", cookie, "", true)
	if r := get(t, base+"/api/state", cookie); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state after logout: %d", r.StatusCode)
	}
}

func TestConsoleNoPassword(t *testing.T) {
	base, _ := startConsole(t, "", "127.0.0.1:1")
	if r := get(t, base+"/api/state", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("state: %d", r.StatusCode)
	}
}

// wsDial is a tiny test client for the console's WebSocket.
func wsDial(t *testing.T, base, origin string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	host := strings.TrimPrefix(base, "http://")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET /api/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: %s\r\n\r\n", host, origin)
	rd := bufio.NewReader(c)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols &&
		resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("bad accept key %q", resp.Header.Get("Sec-WebSocket-Accept"))
	}
	return c, rd, resp.StatusCode
}

func wsReadState(t *testing.T, rd *bufio.Reader) consoleState {
	t.Helper()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(rd, hdr[:]); err != nil {
			t.Fatal(err)
		}
		n := uint64(hdr[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			io.ReadFull(rd, b[:])
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			io.ReadFull(rd, b[:])
			n = binary.BigEndian.Uint64(b[:])
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(rd, payload); err != nil {
			t.Fatal(err)
		}
		if hdr[0]&0x0F != wsOpText {
			continue
		}
		var s consoleState
		if err := json.Unmarshal(payload, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func TestConsoleWebSocketRejectsCrossOrigin(t *testing.T) {
	base, _ := startConsole(t, "", "127.0.0.1:1")
	if _, _, code := wsDial(t, base, "http://evil.example"); code != http.StatusForbidden {
		t.Fatalf("cross-origin handshake: %d", code)
	}
}

// The WebSocket pushes a new state when a pipe opens, and Stop resets both
// legs with RST so the client sees ECONNRESET rather than a clean EOF.
func TestConsolePushAndStop(t *testing.T) {
	upstreamGot := make(chan error, 1)
	target := startServer(t, func(c *net.TCPConn) {
		_, _ = c.Write([]byte("hello"))
		_, err := io.Copy(io.Discard, c)
		upstreamGot <- err
	})
	base, fwd := startConsole(t, "", target)
	_, rd, code := wsDial(t, base, base)
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %d", code)
	}
	if s := wsReadState(t, rd); len(s.Listeners) != 1 || len(s.Listeners[0].Pipes) != 0 {
		t.Fatalf("initial state: %+v", s)
	}

	client := dial(t, fwd)
	_, _ = client.Write([]byte("ping!!"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}

	// Wait for a pushed frame that shows the pipe with all four counters.
	var p pipeSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := wsReadState(t, rd)
		if ps := s.Listeners[0].Pipes; len(ps) == 1 && ps[0].PFToUpstream == 6 && ps[0].PFToClient == 5 {
			p = ps[0]
			break
		}
	}
	if p.ID == 0 || p.ClientToPF != 6 || p.UpstreamToPF != 5 {
		t.Fatalf("pipe counters never arrived: %+v", p)
	}

	if r := post(t, fmt.Sprintf("%s/api/pipes/%d/stop", base, p.ID), "", "", false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("stop without CSRF header: %d", r.StatusCode)
	}
	if r := post(t, fmt.Sprintf("%s/api/pipes/%d/stop", base, p.ID), "", "", true); r.StatusCode != http.StatusNoContent {
		t.Fatalf("stop: %d", r.StatusCode)
	}
	_, err := client.Read(buf)
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("client leg: want ECONNRESET, got %v", err)
	}
	select {
	case err := <-upstreamGot:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("upstream leg: want ECONNRESET, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream leg was not reset")
	}

	// The pipe disappears from the next push.
	for time.Now().Before(deadline.Add(5 * time.Second)) {
		if s := wsReadState(t, rd); len(s.Listeners[0].Pipes) == 0 {
			if s.Listeners[0].BytesUp != 6 || s.Listeners[0].BytesDown != 5 {
				t.Fatalf("closed totals: %+v", s.Listeners[0])
			}
			return
		}
	}
	t.Fatal("stopped pipe still listed")
}

// Every console asset ships inside the binary and nothing references another
// site. The only URL allowed is the SVG XML namespace, which is an
// identifier the browser never fetches.
func TestConsoleAssetsAreSelfContained(t *testing.T) {
	base, _ := startConsole(t, "", "127.0.0.1:1")
	urlPattern := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}`)
	entries, err := fs.ReadDir(consoleFiles, "console")
	if err != nil || len(entries) == 0 {
		t.Fatalf("embedded console files: %v", err)
	}
	for _, e := range entries {
		data, err := fs.ReadFile(consoleFiles, "console/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range urlPattern.FindAllString(string(data), -1) {
			if m != "http://www.w3.org" {
				t.Errorf("%s references an external URL: %s", e.Name(), m)
			}
		}
		r := get(t, base+"/"+e.Name(), "")
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("GET /%s: %d", e.Name(), r.StatusCode)
		}
	}
	r := get(t, base+"/", "")
	r.Body.Close()
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP does not restrict to self: %q", csp)
	}
	if ct := get(t, base+"/logo.svg", "").Header.Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("logo content type %q", ct)
	}
}
