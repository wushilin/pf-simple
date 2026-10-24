package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// call sends one API request with optional headers and returns the status
// and body.
func call(t *testing.T, method, url, body string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// X-API-Token carries the console password: it authorizes like a session
// and, being a custom header, stands in for the CSRF header.
func TestAPIToken(t *testing.T) {
	base, _ := startConsole(t, "xyz123", "127.0.0.1:1")
	if code, body := call(t, "GET", base+"/api/health", ""); code != http.StatusOK || !strings.Contains(body, `"version":"`+version+`"`) {
		t.Fatalf("health needs no auth and reports the version: %d %s", code, body)
	}
	if code, _ := call(t, "GET", base+"/api/listeners", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call(t, "GET", base+"/api/listeners", "", apiTokenHeader, "nope"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	code, body := call(t, "GET", base+"/api/listeners", "", apiTokenHeader, "xyz123")
	if code != http.StatusOK || !strings.Contains(body, `"listen"`) || strings.Contains(body, `"pipes"`) {
		t.Fatalf("listeners with token: %d %s", code, body)
	}
	// A write with the token alone passes the CSRF check and reaches the
	// handler (management is off here, hence 403 from the manager).
	code, body = call(t, "POST", base+"/api/listeners/validate", `{"listen":"1","target":"x"}`, apiTokenHeader, "xyz123")
	if code != http.StatusForbidden || !strings.Contains(body, "config file") {
		t.Fatalf("validate with token: %d %s", code, body)
	}
	if code, _ := call(t, "POST", base+"/api/listeners/validate", `{}`); code != http.StatusForbidden {
		t.Fatalf("write without either header: %d", code)
	}
}

func TestAPIListenersAndConnections(t *testing.T) {
	echo := startServer(t, func(c *net.TCPConn) { _, _ = io.Copy(c, c) })
	_, echoPort, _ := net.SplitHostPort(echo)
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.toml")
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := os.WriteFile(path, []byte(fmt.Sprintf("[console]\nlisten = \"127.0.0.1:%d\"\n\n[[forward]]\nname = \"Echo\"\nlisten = %q\ntarget = \"127.0.0.1:%s\"\n",
		freePort(t), addr, echoPort)), 0o600); err != nil {
		t.Fatal(err)
	}
	base, _ := startFromConfig(t, path)
	csrf := []string{csrfHeader, "1"}

	code, body := call(t, "GET", base+"/api/listeners/0", "")
	if code != http.StatusOK || !strings.Contains(body, `"name":"Echo"`) {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, _ := call(t, "GET", base+"/api/listeners/9", ""); code != http.StatusNotFound {
		t.Fatalf("get missing: %d", code)
	}
	code, body = call(t, "POST", base+"/api/listeners/validate", fmt.Sprintf(`{"listen":%q,"target":"127.0.0.1"}`, addr), csrf...)
	if code != http.StatusBadRequest || !strings.Contains(body, "already used") {
		t.Fatalf("validate a clash: %d %s", code, body)
	}
	code, body = call(t, "POST", base+"/api/listeners/validate?id=0", fmt.Sprintf(`{"listen":%q,"target":"127.0.0.1"}`, addr), csrf...)
	if code != http.StatusOK || !strings.Contains(body, fmt.Sprintf(`"target":"127.0.0.1:%d"`, port)) {
		t.Fatalf("validate as an edit: %d %s", code, body)
	}

	// An open connection shows up in both listings and can be reset.
	c := dial(t, addr)
	defer c.Close()
	var conns []pipeSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for len(conns) == 0 && time.Now().Before(deadline) {
		_, body = call(t, "GET", base+"/api/connections", "")
		_ = json.Unmarshal([]byte(body), &conns)
	}
	if len(conns) != 1 || conns[0].ListenerID != 0 {
		t.Fatalf("connections: %s", body)
	}
	if code, body = call(t, "GET", base+"/api/listeners/0/connections", ""); !strings.Contains(body, fmt.Sprintf(`"id":%d`, conns[0].ID)) {
		t.Fatalf("listener connections: %d %s", code, body)
	}
	if code, _ = call(t, "DELETE", fmt.Sprintf("%s/api/connections/%d", base, conns[0].ID), "", csrf...); code != http.StatusNoContent {
		t.Fatalf("reset: %d", code)
	}

	// Edit and delete need a stopped listener, as in the console.
	spec := fmt.Sprintf(`{"name":"Renamed","listen":%q,"target":"127.0.0.1:%s"}`, addr, echoPort)
	if code, _ = call(t, "PUT", base+"/api/listeners/0", spec, csrf...); code != http.StatusConflict {
		t.Fatalf("edit while running: %d", code)
	}
	if code, _ = call(t, "POST", base+"/api/listeners/0/stop", "", csrf...); code != http.StatusNoContent {
		t.Fatalf("stop: %d", code)
	}
	if code, body = call(t, "PUT", base+"/api/listeners/0", spec, csrf...); code != http.StatusNoContent {
		t.Fatalf("edit: %d %s", code, body)
	}
	if !strings.Contains(readFile(t, path), `name = "Renamed"`) {
		t.Fatalf("edit not saved:\n%s", readFile(t, path))
	}
	if code, _ = call(t, "DELETE", base+"/api/listeners/0", "", csrf...); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, body = call(t, "GET", base+"/api/stats", ""); code != http.StatusOK || !strings.Contains(body, `"listeners":0`) {
		t.Fatalf("stats: %d %s", code, body)
	}
}

// waitFlow polls GET api/flows until a closed connection with this result
// appears.
func waitFlow(t *testing.T, base string, match func(flowView) bool) flowView {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, body := call(t, "GET", base+"/api/flows", "")
		var snap flowSnapshot
		if err := json.Unmarshal([]byte(body), &snap); err != nil {
			t.Fatal(err)
		}
		for _, v := range snap.Closed {
			if match(v) {
				return v
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("flow not recorded")
	return flowView{}
}

// The flow log keeps connections that never became pipes, and how each
// pipe ended.
func TestFlowLogResults(t *testing.T) {
	target := startServer(t, func(c *net.TCPConn) { _, _ = c.Write([]byte("hi")) })
	base, fwd := startConsole(t, "", target)
	c := dial(t, fwd)
	_, _ = io.ReadAll(c)
	c.Close()
	v := waitFlow(t, base, func(v flowView) bool { return v.Client == c.LocalAddr().String() })
	if v.Result != flowClosed || v.BytesDown != 2 || v.UpstreamRemote != target || v.Ended < v.Started {
		t.Fatalf("closed flow: %+v", v)
	}

	_, dead, _ := startConsoleServer(t, "", "127.0.0.1:1")
	d := dial(t, dead)
	_, _ = io.ReadAll(d)
	v = waitFlow(t, base, func(v flowView) bool { return v.Client == d.LocalAddr().String() })
	if v.Result != flowFailed || v.Reason == "" {
		t.Fatalf("failed flow: %+v", v)
	}
}

func TestFlowLogWebSocket(t *testing.T) {
	target := startServer(t, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })
	base, fwd := startConsole(t, "", target)
	host := strings.TrimSuffix(strings.TrimPrefix(base, "http://"), consolePrefix)
	ws, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(ws, "GET %s/api/flows HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", consolePrefix, host)
	rd := bufio.NewReader(ws)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %v %v", resp, err)
	}
	var first flowSnapshot
	if err := json.Unmarshal(wsReadText(t, rd), &first); err != nil || first.Type != "snapshot" || !first.Full {
		t.Fatalf("first message: %+v %v", first, err)
	}

	c := dial(t, fwd)
	want := c.LocalAddr().String()
	c.Close()
	seen := map[string]bool{}
	for !seen["close"] {
		var m struct {
			Type   string      `json:"type"`
			Events []flowEvent `json:"events"`
		}
		if err := json.Unmarshal(wsReadText(t, rd), &m); err != nil {
			t.Fatal(err)
		}
		for _, ev := range m.Events {
			if ev.Flow.Client == want {
				seen[ev.Type] = true
			}
		}
	}
	if !seen["open"] {
		t.Fatalf("no open event before close: %v", seen)
	}
}

// wsReadText returns the next text frame's payload.
func wsReadText(t *testing.T, rd *bufio.Reader) []byte {
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
			_, _ = io.ReadFull(rd, b[:])
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			_, _ = io.ReadFull(rd, b[:])
			n = binary.BigEndian.Uint64(b[:])
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(rd, payload); err != nil {
			t.Fatal(err)
		}
		if hdr[0]&0x0F == wsOpText {
			return payload
		}
	}
}
